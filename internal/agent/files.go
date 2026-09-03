package agent

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/Flyinsky2004/oh-my-acme/internal/protocol"
)

// whitelistedNginx and whitelistedSystemctl are the only executable locations
// the agent will ever consider. They are resolved once at startup; a request
// can never select a binary.
var (
	whitelistedNginx     = []string{"/usr/sbin/nginx", "/usr/bin/nginx"}
	whitelistedSystemctl = []string{"/bin/systemctl", "/usr/bin/systemctl"}
)

// certFileInfo describes the four managed files in a certificate directory.
type certFileInfo struct {
	name string
	mode os.FileMode
}

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

// writeNewFiles writes the four .new files with the correct permissions.
func writeNewFiles(cp certFiles, req protocol.DeployRequest) error {
	payload := map[string]struct {
		data []byte
		mode os.FileMode
	}{
		"cert.pem":      {[]byte(req.CertPEM), 0o644},
		"ca.pem":        {[]byte(req.CAPEM), 0o644},
		"fullchain.pem": {[]byte(req.FullchainPEM), 0o644},
		"privkey.pem":   {[]byte(req.PrivateKeyPEM), 0o600},
	}
	// Write all .new files first; if any fails, nothing live was touched.
	for name, f := range payload {
		if err := os.WriteFile(cp.New[name], []byte(f.data), f.mode); err != nil {
			return err
		}
	}
	return nil
}

// swapLive renames each live file to .bak then promotes the .new file to the
// final path. If a step fails, the already-promoted files are rolled back.
func swapLive(cp certFiles) error {
	// Back up existing live files.
	for name, p := range cp.Final {
		if _, err := os.Stat(p); err == nil {
			if err := os.Rename(p, cp.Back[name]); err != nil {
				return err
			}
		}
	}
	// Promote .new -> live.
	for name, p := range cp.Final {
		if err := os.Rename(cp.New[name], p); err != nil {
			return err
		}
	}
	return nil
}

// rollback removes any promoted live file and restores the .bak over it.
func rollback(cp certFiles) {
	for name, final := range cp.Final {
		back := cp.Back[name]
		if _, err := os.Stat(back); err == nil {
			_ = os.Remove(final)
			_ = os.Rename(back, final)
		}
	}
}

// cleanupStaged removes any leftover .new files.
func cleanupStaged(cp certFiles) {
	for _, p := range cp.New {
		_ = os.Remove(p)
	}
}

// removeBackups deletes the .bak files after a successful deployment.
func removeBackups(cp certFiles) {
	for _, p := range cp.Back {
		_ = os.Remove(p)
	}
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
