package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/Flyinsky2004/oh-my-acme/internal/protocol"
)

// whitelistedNginx and whitelistedSystemctl are the only executable locations
// the agent will ever consider. They are resolved once at startup; a request
// can never select a binary or an argument.
var (
	whitelistedNginx     = []string{"/usr/sbin/nginx", "/usr/bin/nginx"}
	whitelistedSystemctl = []string{"/bin/systemctl", "/usr/bin/systemctl"}
)

// certFileInfo describes one managed file in a certificate directory.
type certFileInfo struct {
	name string
	mode os.FileMode
}

// managedFiles is ordered: staging, promotion, and rollback all use this same
// order so a partial swap is deterministic.
var managedFiles = []certFileInfo{
	{"cert.pem", 0o644},
	{"ca.pem", 0o644},
	{"fullchain.pem", 0o644},
	{"privkey.pem", 0o600},
}

// certFiles holds the final, .new and .bak paths for each managed file.
type certFiles struct {
	Final map[string]string
	New   map[string]string
	Back  map[string]string
}

func certPaths(dir string) certFiles {
	cp := certFiles{
		Final: map[string]string{},
		New:   map[string]string{},
		Back:  map[string]string{},
	}
	for _, mf := range managedFiles {
		p := filepath.Join(dir, mf.name)
		cp.Final[mf.name] = p
		cp.New[mf.name] = p + ".new"
		cp.Back[mf.name] = p + ".bak"
	}
	return cp
}

// stagedPayload maps each managed file to the bytes that should be installed.
func stagedPayload(req protocol.DeployRequest) map[string][]byte {
	return map[string][]byte{
		"cert.pem":      []byte(req.CertPEM),
		"ca.pem":        []byte(req.CAPEM),
		"fullchain.pem": []byte(req.FullchainPEM),
		"privkey.pem":   []byte(req.PrivateKeyPEM),
	}
}

// writeStagedFiles writes all four .new files with the correct permissions.
// Each file is written to a temporary name and renamed into place, so a .new
// file is either complete or absent. Nothing live is touched.
func writeStagedFiles(cp certFiles, req protocol.DeployRequest) error {
	payload := stagedPayload(req)
	for _, mf := range managedFiles {
		if err := writeFileAtomic(cp.New[mf.name], payload[mf.name], mf.mode); err != nil {
			return fmt.Errorf("write %s: %w", cp.New[mf.name], err)
		}
	}
	return nil
}

// writeFileAtomic writes data to a temporary file in the destination directory,
// fsyncs it, and renames it over path.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".oma-tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}
	if err := tmp.Chmod(mode); err != nil {
		cleanup()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return nil
}

// copyFileAtomic copies src to dst through a temporary file, preserving the
// source permissions. Used to create a backup without removing the live file.
func copyFileAtomic(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	dir := filepath.Dir(dst)
	tmp, err := os.CreateTemp(dir, ".oma-bak-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}
	if err := tmp.Chmod(mode); err != nil {
		cleanup()
		return err
	}
	if _, err := io.Copy(tmp, in); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, dst); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return nil
}

// swapState tracks which live files were backed up and which staged files were
// promoted, so a failure can be rolled back precisely.
type swapState struct {
	cp       certFiles
	backedUp map[string]bool
	promoted map[string]bool
}

func newSwapState(cp certFiles) *swapState {
	return &swapState{
		cp:       cp,
		backedUp: map[string]bool{},
		promoted: map[string]bool{},
	}
}

// backupLive copies each existing live file to .bak. The live file stays in
// place, so a failure here leaves the active set untouched. A stale .bak from
// an earlier interrupted deployment is moved to .bak.recover instead of being
// overwritten; if both already exist, the deployment is refused so a
// recoverable copy is never silently lost.
func backupLive(st *swapState) error {
	for _, mf := range managedFiles {
		name := mf.name
		final := st.cp.Final[name]
		back := st.cp.Back[name]

		fi, err := os.Lstat(final)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect %s: %w", final, err)
		}
		if !fi.Mode().IsRegular() {
			return fmt.Errorf("refusing to replace non-regular file %s", final)
		}

		if _, err := os.Lstat(back); err == nil {
			recoverPath := back + ".recover"
			if _, statErr := os.Lstat(recoverPath); statErr == nil {
				return fmt.Errorf("stale backup %s and %s both exist; remove one before deploying", back, recoverPath)
			} else if !errors.Is(statErr, os.ErrNotExist) {
				return fmt.Errorf("inspect %s: %w", recoverPath, statErr)
			}
			if err := os.Rename(back, recoverPath); err != nil {
				return fmt.Errorf("preserve stale backup %s: %w", back, err)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect backup %s: %w", back, err)
		}

		if err := copyFileAtomic(final, back, fi.Mode().Perm()); err != nil {
			return fmt.Errorf("back up %s: %w", final, err)
		}
		st.backedUp[name] = true
	}
	return nil
}

// promote atomically renames each .new file over its live path. On failure the
// caller must call rollback.
func promote(st *swapState) error {
	for _, mf := range managedFiles {
		name := mf.name
		if err := os.Rename(st.cp.New[name], st.cp.Final[name]); err != nil {
			return fmt.Errorf("replace %s: %w", st.cp.Final[name], err)
		}
		st.promoted[name] = true
	}
	return nil
}

// rollback restores the previous live files. Files that were backed up are
// restored from .bak; files promoted during a first deployment (no backup) are
// removed. All failures are returned; a backup that could not be restored is
// left on disk for manual recovery.
func rollback(st *swapState) error {
	var errs []error
	for i := len(managedFiles) - 1; i >= 0; i-- {
		name := managedFiles[i].name
		final := st.cp.Final[name]
		back := st.cp.Back[name]
		if st.backedUp[name] {
			fi, statErr := os.Lstat(back)
			if statErr != nil {
				errs = append(errs, fmt.Errorf("inspect backup %s: %w", back, statErr))
				continue
			}
			if !fi.Mode().IsRegular() {
				errs = append(errs, fmt.Errorf("backup %s is not a regular file", back))
				continue
			}
			if err := os.Rename(back, final); err != nil {
				errs = append(errs, fmt.Errorf("restore %s from %s: %w", final, back, err))
			}
			continue
		}
		if st.promoted[name] {
			if err := os.Remove(final); err != nil && !errors.Is(err, os.ErrNotExist) {
				errs = append(errs, fmt.Errorf("remove first-deploy file %s: %w", final, err))
			}
		}
	}
	return errors.Join(errs...)
}

// discardBackups removes backups created by a failed backup phase. The live
// files were never touched, so these copies are not needed.
func discardBackups(st *swapState) error {
	var errs []error
	for name := range st.backedUp {
		if err := os.Remove(st.cp.Back[name]); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, fmt.Errorf("remove backup %s: %w", st.cp.Back[name], err))
		}
	}
	return errors.Join(errs...)
}

// cleanupStaged removes any leftover .new files and returns every failure.
func cleanupStaged(cp certFiles) error {
	var errs []error
	for _, mf := range managedFiles {
		p := cp.New[mf.name]
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, fmt.Errorf("remove staged %s: %w", p, err))
		}
	}
	return errors.Join(errs...)
}

// commit removes the backups after a successful deployment. Failures are
// returned so the caller can log them; the deployment itself already succeeded.
func commit(st *swapState) error {
	var errs []error
	for _, mf := range managedFiles {
		name := mf.name
		for _, p := range []string{st.cp.Back[name], st.cp.Back[name] + ".recover"} {
			if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
				errs = append(errs, fmt.Errorf("remove backup %s: %w", p, err))
			}
		}
	}
	return errors.Join(errs...)
}

// runCommand executes a fixed binary + args with the request context. Output
// is capped to keep memory bounded. This is the only execution path in the
// agent; no value from a request is ever used to build the command.
func runCommand(ctx context.Context, bin string, args []string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	out, err := cmd.CombinedOutput()
	if len(out) > 8192 {
		out = out[:8192]
	}
	return out, err
}
