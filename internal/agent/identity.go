package agent

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// fileWrite is one member of an all-or-nothing file transaction.
type fileWrite struct {
	path string
	data []byte
	mode os.FileMode
}

// fileSnapshot is the previous content of a path. Existing files are copied to
// a private backup file in the same directory before any promotion, so a
// rollback is a rename and does not depend on writing new bytes.
type fileSnapshot struct {
	path    string
	backup  string
	mode    os.FileMode
	existed bool
}

// writeFilesAtomicRenameHook is a test seam invoked before each promotion. It
// is nil in production; tests use it to force a failure after earlier files
// have already been promoted and verify the rollback path.
var writeFilesAtomicRenameHook func(index int) error

// identityRestoreRenameHook is a test seam invoked before restoring a backup.
// It is nil in production.
var identityRestoreRenameHook func(target, backup string) error

// IdentityCleanupError means all identity/config replacements committed, but
// an old private backup could not be removed. Callers must report the cleanup
// problem without retrying registration or treating the committed identity as
// an incomplete transaction.
type IdentityCleanupError struct{ Err error }

func (e *IdentityCleanupError) Error() string {
	return "identity committed; backup cleanup required: " + e.Err.Error()
}

func (e *IdentityCleanupError) Unwrap() error { return e.Err }

var removeIdentityBackup = os.Remove

// SaveIdentity writes the agent's identity certificate and the CA trust anchor
// to their configured files, using the key the agent generated locally.
//
// The material is validated first and the files are replaced as one
// transaction: if any write or rename fails, every file that was already
// replaced is restored to its previous content, so a failed registration can
// never overwrite a working identity.
func SaveIdentity(cfg Config, reg *Registration, keyPEM []byte) error {
	writes, err := identityWrites(cfg, reg, keyPEM)
	if err != nil {
		return err
	}
	return writeFilesAtomic(writes)
}

// SaveIdentityAndConfig persists the identity files and config.json as a
// single rollback-safe transaction. This is what the registration command
// uses: a failure to write config.json must not leave new identity files (or a
// cleared token) behind, and a failure to write identity files must not leave
// a partially updated config.
func SaveIdentityAndConfig(cfg Config, reg *Registration, keyPEM []byte, configPath string, next Config) error {
	if strings.TrimSpace(configPath) == "" {
		return errors.New("config path is required")
	}
	writes, err := identityWrites(cfg, reg, keyPEM)
	if err != nil {
		return err
	}
	configJSON, err := json.MarshalIndent(&next, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	writes = append(writes, fileWrite{path: configPath, data: configJSON, mode: 0o600})
	return writeFilesAtomic(writes)
}

// identityWrites validates the identity material and returns the files to
// write. CAFile and ServerCAFile may point at the same path (the default); in
// that case the file carries both CAs when they differ.
func identityWrites(cfg Config, reg *Registration, keyPEM []byte) ([]fileWrite, error) {
	if err := validateIdentityMaterial(reg, keyPEM); err != nil {
		return nil, err
	}
	if cfg.CertFile == "" || cfg.KeyFile == "" || cfg.ServerCAFile == "" {
		return nil, errors.New("config: cert_file, key_file and server_ca_file are required")
	}
	serverCA := reg.ServerCAPEM
	if len(serverCA) == 0 {
		serverCA = reg.CAPEM
	}
	issuingCA := reg.CAPEM
	if len(issuingCA) == 0 {
		issuingCA = serverCA
	}
	writes := []fileWrite{
		{path: cfg.CertFile, data: reg.CertPEM, mode: 0o644},
		{path: cfg.KeyFile, data: keyPEM, mode: 0o600},
	}
	if cfg.CAFile != "" && cfg.CAFile == cfg.ServerCAFile {
		data := serverCA
		if !bytes.Equal(issuingCA, serverCA) {
			data = append(append([]byte(nil), issuingCA...), serverCA...)
		}
		writes = append(writes, fileWrite{path: cfg.ServerCAFile, data: data, mode: 0o644})
	} else {
		writes = append(writes, fileWrite{path: cfg.ServerCAFile, data: serverCA, mode: 0o644})
		if cfg.CAFile != "" {
			writes = append(writes, fileWrite{path: cfg.CAFile, data: issuingCA, mode: 0o644})
		}
	}
	return writes, nil
}

// validateIdentityMaterial rejects a certificate/key/CA combination that must
// never be written to disk: mismatched key, non-CA trust anchor, wrong
// signature, wrong purpose or expired certificate.
func validateIdentityMaterial(reg *Registration, keyPEM []byte) error {
	if reg == nil {
		return errors.New("missing registration")
	}
	if len(reg.CertPEM) == 0 {
		return errors.New("missing agent certificate")
	}
	if len(keyPEM) == 0 {
		return errors.New("missing agent private key")
	}
	leaf, err := parseSingleCertificatePEM(reg.CertPEM)
	if err != nil {
		return fmt.Errorf("invalid agent certificate: %w", err)
	}
	pub, err := publicKeyFromPrivateKeyPEM(keyPEM)
	if err != nil {
		return err
	}
	if !publicKeysEqual(leaf.PublicKey, pub) {
		return errors.New("agent certificate does not match the private key")
	}
	issuingCA, err := parseSingleCertificatePEM(reg.CAPEM)
	if err != nil {
		return fmt.Errorf("invalid issuing CA: %w", err)
	}
	if !issuingCA.IsCA {
		return errors.New("issuing CA certificate is not a CA")
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) {
		return errors.New("agent certificate is not yet valid")
	}
	if !now.Before(leaf.NotAfter) {
		return errors.New("agent certificate has expired")
	}
	if !hasExtKeyUsage(leaf, x509.ExtKeyUsageServerAuth) {
		return errors.New("agent certificate is not valid for server authentication")
	}
	roots := x509.NewCertPool()
	roots.AddCert(issuingCA)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return fmt.Errorf("agent certificate is not signed by the CA: %w", err)
	}
	if len(reg.ServerCAPEM) > 0 {
		serverCA, err := parseSingleCertificatePEM(reg.ServerCAPEM)
		if err != nil {
			return fmt.Errorf("invalid server CA: %w", err)
		}
		if !serverCA.IsCA {
			return errors.New("server CA certificate is not a CA")
		}
		serverRoots := x509.NewCertPool()
		serverRoots.AddCert(serverCA)
		if _, err := leaf.Verify(x509.VerifyOptions{
			Roots:       serverRoots,
			CurrentTime: now,
			KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}); err != nil {
			return fmt.Errorf("server CA does not match the agent certificate issuer: %w", err)
		}
	}
	return nil
}

// writeFilesAtomic writes every file or restores the previous contents.
//
// Existing files are first copied to private backup files in the same
// directory, then all new contents are written to temp files, and only then
// are the live paths promoted by rename. A failure before promotion leaves
// every live file untouched. A failure during promotion restores already
// promoted files by renaming their backups back; if such a restore fails, the
// backup path is preserved and reported so the old identity is not lost.
func writeFilesAtomic(writes []fileWrite) error {
	if len(writes) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(writes))
	for _, w := range writes {
		if strings.TrimSpace(w.path) == "" {
			return errors.New("empty file path")
		}
		clean := filepath.Clean(w.path)
		if _, ok := seen[clean]; ok {
			return fmt.Errorf("duplicate file path %q", w.path)
		}
		seen[clean] = struct{}{}
	}

	snapshots := make([]fileSnapshot, len(writes))
	temps := make([]string, len(writes))
	cleanupTemps := func() {
		for i, p := range temps {
			if p != "" {
				_ = os.Remove(p)
				temps[i] = ""
			}
		}
	}
	cleanupBackups := func(from int) {
		for i := from; i < len(snapshots); i++ {
			if snapshots[i].backup != "" {
				_ = os.Remove(snapshots[i].backup)
				snapshots[i].backup = ""
			}
		}
	}

	// Prepare backups before touching anything live. If any backup cannot be
	// created, no live file has been changed.
	for i, w := range writes {
		snapshots[i].path = w.path
		fi, err := os.Lstat(w.path)
		switch {
		case err == nil:
			if fi.Mode()&os.ModeSymlink != 0 {
				cleanupBackups(0)
				return fmt.Errorf("%s is a symlink", w.path)
			}
			if !fi.Mode().IsRegular() {
				cleanupBackups(0)
				return fmt.Errorf("%s is not a regular file", w.path)
			}
			old, readErr := os.ReadFile(w.path)
			if readErr != nil {
				cleanupBackups(0)
				return fmt.Errorf("read existing %s: %w", w.path, readErr)
			}
			backup, backupErr := createBackupFile(w.path, old)
			if backupErr != nil {
				cleanupBackups(0)
				return fmt.Errorf("back up existing %s: %w", w.path, backupErr)
			}
			snapshots[i].existed = true
			snapshots[i].backup = backup
			snapshots[i].mode = fi.Mode().Perm()
		case os.IsNotExist(err):
		default:
			cleanupBackups(0)
			return fmt.Errorf("stat %s: %w", w.path, err)
		}
		if err := os.MkdirAll(filepath.Dir(w.path), 0o700); err != nil {
			cleanupBackups(0)
			return fmt.Errorf("create directory for %s: %w", w.path, err)
		}
	}

	for i, w := range writes {
		tmp, err := createTempFile(w.path, w.data, w.mode)
		if err != nil {
			cleanupTemps()
			cleanupBackups(0)
			return fmt.Errorf("write %s: %w", w.path, err)
		}
		temps[i] = tmp
	}

	fail := func(index int, cause error) error {
		rollbackErr := rollbackFiles(snapshots, index)
		cleanupTemps()
		// Backups for files that were never promoted are no longer needed.
		cleanupBackups(index)
		if rollbackErr != nil {
			return fmt.Errorf("replace %s: %w; rollback incomplete: %v", writes[index].path, cause, rollbackErr)
		}
		return fmt.Errorf("replace %s: %w", writes[index].path, cause)
	}
	for i, w := range writes {
		if writeFilesAtomicRenameHook != nil {
			if err := writeFilesAtomicRenameHook(i); err != nil {
				return fail(i, err)
			}
		}
		if err := os.Rename(temps[i], w.path); err != nil {
			return fail(i, err)
		}
		temps[i] = ""
	}

	// Success: the old copies are no longer needed.
	var cleanupErrors []error
	for i := range snapshots {
		if snapshots[i].backup == "" {
			continue
		}
		if err := removeIdentityBackup(snapshots[i].backup); err != nil {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("remove identity backup %s: %w", snapshots[i].backup, err))
		}
		snapshots[i].backup = ""
	}
	if err := errors.Join(cleanupErrors...); err != nil {
		return &IdentityCleanupError{Err: err}
	}
	return nil
}

// rollbackFiles restores the first promoted files. Backups are renamed back
// into place, so a full disk cannot prevent the restore. A failed restore
// keeps its backup path in the returned error.
func rollbackFiles(snapshots []fileSnapshot, promoted int) error {
	var problems []string
	for i := 0; i < promoted; i++ {
		snapshot := &snapshots[i]
		if snapshot.existed {
			if identityRestoreRenameHook != nil {
				if err := identityRestoreRenameHook(snapshot.path, snapshot.backup); err != nil {
					problems = append(problems, fmt.Sprintf("restore %s from %s: %v", snapshot.path, snapshot.backup, err))
					continue
				}
			}
			if err := os.Rename(snapshot.backup, snapshot.path); err != nil {
				problems = append(problems, fmt.Sprintf("restore %s from %s: %v", snapshot.path, snapshot.backup, err))
				continue
			}
			if err := os.Chmod(snapshot.path, snapshot.mode); err != nil {
				problems = append(problems, fmt.Sprintf("restore mode %s: %v", snapshot.path, err))
			}
			snapshot.backup = ""
			continue
		}
		if err := os.Remove(snapshot.path); err != nil && !os.IsNotExist(err) {
			problems = append(problems, fmt.Sprintf("remove %s: %v", snapshot.path, err))
		}
	}
	if len(problems) != 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}

// createTempFile writes data to a new uniquely named file next to path and
// returns its name. os.CreateTemp avoids reusing a predictable name and never
// truncates an existing file.
func createTempFile(path string, data []byte, mode os.FileMode) (string, error) {
	return writeTempFile(filepath.Dir(path), filepath.Base(path)+".tmp-*", data, mode)
}

// createBackupFile stores the previous contents of path in a private temp file
// in the same directory.
func createBackupFile(path string, data []byte) (string, error) {
	return writeTempFile(filepath.Dir(path), filepath.Base(path)+".bak-*", data, 0o600)
}

func writeTempFile(dir, pattern string, data []byte, mode os.FileMode) (string, error) {
	f, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return "", err
	}
	name := f.Name()
	cleanup := func() {
		_ = f.Close()
		_ = os.Remove(name)
	}
	if err := f.Chmod(mode); err != nil {
		cleanup()
		return "", err
	}
	if _, err := f.Write(data); err != nil {
		cleanup()
		return "", err
	}
	if err := f.Sync(); err != nil {
		cleanup()
		return "", err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(name)
		return "", err
	}
	return name, nil
}
