package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Flyinsky2004/oh-my-acme/internal/protocol"
)

type commandCall struct {
	bin  string
	args []string
}

type fakeRunner struct {
	mu    sync.Mutex
	calls []commandCall
	fn    func(context.Context, string, []string) ([]byte, error)
}

func (f *fakeRunner) run(ctx context.Context, bin string, args []string) ([]byte, error) {
	f.mu.Lock()
	f.calls = append(f.calls, commandCall{bin: bin, args: append([]string(nil), args...)})
	f.mu.Unlock()
	if f.fn != nil {
		return f.fn(ctx, bin, args)
	}
	return nil, nil
}

func (f *fakeRunner) snapshot() []commandCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]commandCall(nil), f.calls...)
}

func newTestAgent(t *testing.T, certDir string, runner commandRunner) *Agent {
	t.Helper()
	a, err := New(Config{
		CertDir:      certDir,
		CertFile:     filepath.Join(certDir, "identity.crt"),
		KeyFile:      filepath.Join(certDir, "identity.key"),
		ServerCAFile: filepath.Join(certDir, "identity-ca.crt"),
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	// Never touch a real nginx/systemctl, even on a host that has them.
	a.nginxInstalled = false
	a.nginxPath = ""
	a.systemctlPath = ""
	a.runFn = runner
	a.nginxTimeout = time.Second
	return a
}

func enableNginx(a *Agent, runner commandRunner) {
	a.nginxInstalled = true
	a.nginxPath = "/usr/sbin/nginx"
	a.systemctlPath = "/bin/systemctl"
	a.runFn = runner
}

func writeOldFiles(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, mf := range managedFiles {
		if err := os.WriteFile(filepath.Join(dir, mf.name), []byte("old-"+mf.name), mf.mode); err != nil {
			t.Fatal(err)
		}
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func assertOldFiles(t *testing.T, dir string) {
	t.Helper()
	for _, mf := range managedFiles {
		if got, want := readFile(t, filepath.Join(dir, mf.name)), "old-"+mf.name; got != want {
			t.Errorf("%s = %q, want %q", mf.name, got, want)
		}
	}
}

func assertNoLeftovers(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		name := e.Name()
		for _, suffix := range []string{".new", ".bak", ".recover"} {
			if strings.HasSuffix(name, suffix) {
				t.Errorf("unexpected leftover %s", name)
			}
		}
		if strings.HasPrefix(name, ".oma-tmp-") || strings.HasPrefix(name, ".oma-bak-") {
			t.Errorf("unexpected temp file %s", name)
		}
	}
}

func TestDeployFirstInstallWritesFiles(t *testing.T) {
	dir := t.TempDir()
	a := newTestAgent(t, dir, nil)
	chain := newTestChain(t, leafSpec{})

	resp := a.deploy(chain.request("example.com"))
	if !resp.Success {
		t.Fatalf("deploy failed: %+v", resp)
	}
	if resp.NginxStatus != "not-found" {
		t.Fatalf("nginx status = %q, want not-found", resp.NginxStatus)
	}
	certDir := filepath.Join(dir, "example.com")
	for _, mf := range managedFiles {
		p := filepath.Join(certDir, mf.name)
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatalf("%s: %v", mf.name, err)
		}
		if fi.Mode().Perm() != mf.mode {
			t.Errorf("%s mode = %o, want %o", mf.name, fi.Mode().Perm(), mf.mode)
		}
	}
	if got := readFile(t, filepath.Join(certDir, "cert.pem")); got != chain.certPEM {
		t.Error("cert.pem content mismatch")
	}
	if got := readFile(t, filepath.Join(certDir, "fullchain.pem")); got != chain.fullchainPEM {
		t.Error("fullchain.pem content mismatch")
	}
	if got := readFile(t, filepath.Join(certDir, "ca.pem")); got != chain.caPEM {
		t.Error("ca.pem content mismatch")
	}
	if got := readFile(t, filepath.Join(certDir, "privkey.pem")); got != chain.keyPEM {
		t.Error("privkey.pem content mismatch")
	}
	assertNoLeftovers(t, certDir)
}

func TestDeployNginxValidatesThenReloads(t *testing.T) {
	dir := t.TempDir()
	runner := &fakeRunner{}
	a := newTestAgent(t, dir, runner.run)
	enableNginx(a, runner.run)
	certDir := filepath.Join(dir, "example.com")
	writeOldFiles(t, certDir)

	chain := newTestChain(t, leafSpec{})
	resp := a.deploy(chain.request("example.com"))
	if !resp.Success {
		t.Fatalf("deploy failed: %+v", resp)
	}
	if resp.NginxStatus != "ok" {
		t.Fatalf("nginx status = %q, want ok", resp.NginxStatus)
	}

	calls := runner.snapshot()
	want := []commandCall{
		{bin: "/usr/sbin/nginx", args: []string{"-t"}},
		{bin: "/bin/systemctl", args: []string{"reload", "nginx"}},
	}
	if len(calls) != len(want) {
		t.Fatalf("calls = %+v, want %+v", calls, want)
	}
	for i := range want {
		if calls[i].bin != want[i].bin || strings.Join(calls[i].args, " ") != strings.Join(want[i].args, " ") {
			t.Fatalf("call %d = %+v, want %+v", i, calls[i], want[i])
		}
	}
	for _, call := range calls {
		for _, arg := range call.args {
			if arg == "restart" {
				t.Fatal("deploy must reload, never restart")
			}
		}
	}

	if got := readFile(t, filepath.Join(certDir, "cert.pem")); got != chain.certPEM {
		t.Error("cert.pem was not replaced")
	}
	assertNoLeftovers(t, certDir)
}

func TestDeployValidationFailureDoesNotReloadAndRestoresOldFiles(t *testing.T) {
	dir := t.TempDir()
	runner := &fakeRunner{fn: func(context.Context, string, []string) ([]byte, error) {
		return []byte("nginx: bad config"), errors.New("exit status 1")
	}}
	a := newTestAgent(t, dir, runner.run)
	enableNginx(a, runner.run)
	certDir := filepath.Join(dir, "example.com")
	writeOldFiles(t, certDir)

	resp := a.deploy(newTestChain(t, leafSpec{}).request("example.com"))
	if resp.Success {
		t.Fatal("deploy unexpectedly succeeded")
	}
	if resp.NginxStatus != "failed" {
		t.Fatalf("nginx status = %q, want failed", resp.NginxStatus)
	}
	calls := runner.snapshot()
	if len(calls) != 1 || calls[0].bin != "/usr/sbin/nginx" || strings.Join(calls[0].args, " ") != "-t" {
		t.Fatalf("expected only nginx -t, got %+v", calls)
	}
	if !strings.Contains(resp.Error, "validation failed") {
		t.Fatalf("error = %q, want validation failure", resp.Error)
	}
	if !strings.Contains(resp.Error, "rollback: ok") {
		t.Fatalf("error = %q, want rollback ok", resp.Error)
	}
	assertOldFiles(t, certDir)
	assertNoLeftovers(t, certDir)
}

func TestDeployFirstInstallValidationFailureRemovesFiles(t *testing.T) {
	dir := t.TempDir()
	runner := &fakeRunner{fn: func(context.Context, string, []string) ([]byte, error) {
		return nil, errors.New("exit status 1")
	}}
	a := newTestAgent(t, dir, runner.run)
	enableNginx(a, runner.run)

	resp := a.deploy(newTestChain(t, leafSpec{}).request("example.com"))
	if resp.Success {
		t.Fatal("deploy unexpectedly succeeded")
	}
	certDir := filepath.Join(dir, "example.com")
	for _, mf := range managedFiles {
		if _, err := os.Stat(filepath.Join(certDir, mf.name)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s should not exist after a failed first deploy", mf.name)
		}
	}
	assertNoLeftovers(t, certDir)
}

func TestDeployReloadFailureRollsBackAndRecovers(t *testing.T) {
	dir := t.TempDir()
	reloads := 0
	runner := &fakeRunner{fn: func(_ context.Context, bin string, args []string) ([]byte, error) {
		if bin == "/bin/systemctl" && len(args) == 2 && args[0] == "reload" {
			reloads++
			if reloads == 1 {
				return []byte("reload failed"), errors.New("exit status 1")
			}
		}
		return nil, nil
	}}
	a := newTestAgent(t, dir, runner.run)
	enableNginx(a, runner.run)
	certDir := filepath.Join(dir, "example.com")
	writeOldFiles(t, certDir)

	resp := a.deploy(newTestChain(t, leafSpec{}).request("example.com"))
	if resp.Success {
		t.Fatal("deploy unexpectedly succeeded")
	}
	if resp.NginxStatus != "failed" {
		t.Fatalf("nginx status = %q, want failed", resp.NginxStatus)
	}
	calls := runner.snapshot()
	if len(calls) != 4 {
		t.Fatalf("calls = %+v, want validation+reload+recovery validation+recovery reload", calls)
	}
	if !strings.Contains(resp.Error, "nginx reload failed") ||
		!strings.Contains(resp.Error, "rollback: ok") ||
		!strings.Contains(resp.Error, "recovery: ok") {
		t.Fatalf("error = %q, want reload/rollback/recovery details", resp.Error)
	}
	assertOldFiles(t, certDir)
	assertNoLeftovers(t, certDir)
}

func TestDeployReloadFailureRecoveryFailureReported(t *testing.T) {
	dir := t.TempDir()
	runner := &fakeRunner{fn: func(_ context.Context, bin string, args []string) ([]byte, error) {
		if bin == "/bin/systemctl" && len(args) == 2 && args[0] == "reload" {
			return []byte("reload failed"), errors.New("exit status 1")
		}
		return nil, nil
	}}
	a := newTestAgent(t, dir, runner.run)
	enableNginx(a, runner.run)
	certDir := filepath.Join(dir, "example.com")
	writeOldFiles(t, certDir)

	resp := a.deploy(newTestChain(t, leafSpec{}).request("example.com"))
	if resp.Success {
		t.Fatal("deploy unexpectedly succeeded")
	}
	if !strings.Contains(resp.Error, "recovery failed") {
		t.Fatalf("error = %q, want recovery failure", resp.Error)
	}
	assertOldFiles(t, certDir)
	assertNoLeftovers(t, certDir)
}

func TestDeployReloadFailureWithRollbackFailureSkipsRecovery(t *testing.T) {
	dir := t.TempDir()
	certDir := filepath.Join(dir, "example.com")
	writeOldFiles(t, certDir)
	runner := &fakeRunner{fn: func(_ context.Context, bin string, args []string) ([]byte, error) {
		if bin == "/bin/systemctl" && len(args) == 2 && args[0] == "reload" {
			// Sabotage rollback: replace the live privkey with a directory so
			// restoring it from .bak fails.
			final := filepath.Join(certDir, "privkey.pem")
			if err := os.Remove(final); err == nil {
				_ = os.Mkdir(final, 0o700)
				_ = os.WriteFile(filepath.Join(final, "block"), []byte("x"), 0o600)
			}
			return nil, errors.New("reload failed")
		}
		return nil, nil
	}}
	a := newTestAgent(t, dir, runner.run)
	enableNginx(a, runner.run)

	resp := a.deploy(newTestChain(t, leafSpec{}).request("example.com"))
	if resp.Success {
		t.Fatal("deploy unexpectedly succeeded")
	}
	if !strings.Contains(resp.Error, "rollback failed") {
		t.Fatalf("error = %q, want rollback failure", resp.Error)
	}
	if strings.Contains(resp.Error, "recovery: ok") {
		t.Fatalf("error = %q, recovery must be skipped after a failed rollback", resp.Error)
	}
	if !strings.Contains(resp.Log, "skipping service recovery") {
		t.Fatalf("log = %q, want explicit uncertainty note", resp.Log)
	}
}

func TestDeployReloadTimeoutRollsBackAndRecovers(t *testing.T) {
	dir := t.TempDir()
	reloads := 0
	runner := &fakeRunner{fn: func(ctx context.Context, bin string, args []string) ([]byte, error) {
		if bin == "/bin/systemctl" && len(args) == 2 && args[0] == "reload" {
			reloads++
			if reloads == 1 {
				<-ctx.Done()
				return nil, ctx.Err()
			}
		}
		return nil, nil
	}}
	a := newTestAgent(t, dir, runner.run)
	enableNginx(a, runner.run)
	a.nginxTimeout = 50 * time.Millisecond
	certDir := filepath.Join(dir, "example.com")
	writeOldFiles(t, certDir)

	resp := a.deploy(newTestChain(t, leafSpec{}).request("example.com"))
	if resp.Success {
		t.Fatal("deploy unexpectedly succeeded")
	}
	if !strings.Contains(resp.Error, "timed out") {
		t.Fatalf("error = %q, want timeout", resp.Error)
	}
	if !strings.Contains(resp.Error, "rollback: ok") || !strings.Contains(resp.Error, "recovery: ok") {
		t.Fatalf("error = %q, want rollback and recovery details", resp.Error)
	}
	assertOldFiles(t, certDir)
	assertNoLeftovers(t, certDir)
}

func TestDeployRejectsBadMaterialWithoutTouchingFiles(t *testing.T) {
	dir := t.TempDir()
	runner := &fakeRunner{}
	a := newTestAgent(t, dir, runner.run)
	enableNginx(a, runner.run)
	certDir := filepath.Join(dir, "example.com")
	writeOldFiles(t, certDir)

	chain := newTestChain(t, leafSpec{})
	req := chain.request("example.com")
	req.FullchainPEM = chain.certPEM // missing issuer

	resp := a.deploy(req)
	if resp.Success {
		t.Fatal("deploy unexpectedly succeeded")
	}
	if calls := runner.snapshot(); len(calls) != 0 {
		t.Fatalf("no command should run for bad material, got %+v", calls)
	}
	assertOldFiles(t, certDir)
	assertNoLeftovers(t, certDir)
}

func TestPromotePartialFailureRollsBack(t *testing.T) {
	dir := t.TempDir()
	cp := certPaths(dir)
	writeOldFiles(t, dir)
	req := newTestChain(t, leafSpec{}).request("example.com")
	if err := writeStagedFiles(cp, req); err != nil {
		t.Fatal(err)
	}
	st := newSwapState(cp)
	if err := backupLive(st); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(cp.New["privkey.pem"]); err != nil {
		t.Fatal(err)
	}
	if err := promote(st); err == nil {
		t.Fatal("expected promote failure")
	}
	if err := rollback(st); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	assertOldFiles(t, dir)
	if err := cleanupStaged(cp); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	assertNoLeftovers(t, dir)
}

func TestFirstDeployPartialFailureRemovesPromotedFiles(t *testing.T) {
	dir := t.TempDir()
	cp := certPaths(dir)
	req := newTestChain(t, leafSpec{}).request("example.com")
	if err := writeStagedFiles(cp, req); err != nil {
		t.Fatal(err)
	}
	st := newSwapState(cp)
	if err := backupLive(st); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(cp.New["privkey.pem"]); err != nil {
		t.Fatal(err)
	}
	if err := promote(st); err == nil {
		t.Fatal("expected promote failure")
	}
	if err := rollback(st); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	for _, mf := range managedFiles {
		if _, err := os.Stat(cp.Final[mf.name]); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s should not exist after a failed first deploy", mf.name)
		}
	}
	if err := cleanupStaged(cp); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	assertNoLeftovers(t, dir)
}

func TestRollbackFailureIsReportedAndBackupPreserved(t *testing.T) {
	dir := t.TempDir()
	cp := certPaths(dir)
	writeOldFiles(t, dir)
	req := newTestChain(t, leafSpec{}).request("example.com")
	if err := writeStagedFiles(cp, req); err != nil {
		t.Fatal(err)
	}
	st := newSwapState(cp)
	if err := backupLive(st); err != nil {
		t.Fatal(err)
	}
	if err := promote(st); err != nil {
		t.Fatal(err)
	}

	// Make restoring privkey.pem fail: replace the live path with a directory.
	final := cp.Final["privkey.pem"]
	if err := os.Remove(final); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(final, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(final, "block"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := rollback(st)
	if err == nil {
		t.Fatal("expected rollback error")
	}
	if !strings.Contains(err.Error(), "restore") {
		t.Fatalf("error = %q, want restore failure", err)
	}
	if _, statErr := os.Stat(cp.Back["privkey.pem"]); statErr != nil {
		t.Fatalf("recoverable backup should be preserved: %v", statErr)
	}
}

func TestCleanupFailureIsReported(t *testing.T) {
	dir := t.TempDir()
	cp := certPaths(dir)
	if err := os.Mkdir(cp.New["cert.pem"], 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cp.New["cert.pem"], "x"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cleanupStaged(cp); err == nil {
		t.Fatal("expected cleanup error")
	}
}

func TestBackupPreservesStaleBackup(t *testing.T) {
	dir := t.TempDir()
	cp := certPaths(dir)
	writeOldFiles(t, dir)
	if err := os.WriteFile(cp.Back["cert.pem"], []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}

	st := newSwapState(cp)
	if err := backupLive(st); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, cp.Back["cert.pem"]+".recover"); got != "stale" {
		t.Fatalf("recover copy = %q, want stale", got)
	}
	if got := readFile(t, cp.Back["cert.pem"]); got != "old-cert.pem" {
		t.Fatalf("new backup = %q, want old-cert.pem", got)
	}

	// Both .bak and .bak.recover now exist: refuse rather than overwrite.
	if err := backupLive(newSwapState(cp)); err == nil {
		t.Fatal("expected stale-backup error")
	}
}

func TestDeploySerializesConcurrentRequests(t *testing.T) {
	dir := t.TempDir()
	var active, maxActive atomic.Int32
	runner := &fakeRunner{fn: func(context.Context, string, []string) ([]byte, error) {
		n := active.Add(1)
		for {
			m := maxActive.Load()
			if n <= m || maxActive.CompareAndSwap(m, n) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
		active.Add(-1)
		return nil, nil
	}}
	a := newTestAgent(t, dir, runner.run)
	enableNginx(a, runner.run)

	body, err := json.Marshal(newTestChain(t, leafSpec{}).request("example.com"))
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodPost, protocol.AgentAPIPrefix+"/deploy", bytes.NewReader(body))
			rw := httptest.NewRecorder()
			a.handleDeploy(rw, req)
			if rw.Code != http.StatusOK {
				t.Errorf("status = %d, want 200", rw.Code)
			}
		}()
	}
	wg.Wait()
	if got := maxActive.Load(); got != 1 {
		t.Fatalf("max concurrent commands = %d, want 1", got)
	}
}
