// Package agent is the on-machine certificate deployment agent. It exposes a
// small mTLS HTTP API through which the server pushes certificate versions.
// The agent writes PEM files into a fixed directory and, if nginx is present
// and already configured to reference those paths, runs a validation +
// reload. It executes no arbitrary commands: the only programs ever launched
// are a hard-coded nginx "-t", "systemctl reload nginx", and the non-systemd
// "nginx -s reload" fallback.
package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/Flyinsky2004/oh-my-acme/internal/protocol"
	"github.com/Flyinsky2004/oh-my-acme/internal/updater"
)

// Version is set at build time via -ldflags.
var Version = "dev"

// ErrRestart asks main to exit with a non-zero status after self-update so
// systemd's fixed Restart=on-failure policy starts the new binary.
var ErrRestart = errors.New("restart requested")

var safeDomain = regexp.MustCompile(`^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+$`)

// commandRunner executes a fixed binary with fixed arguments. It exists only
// so tests can observe and simulate command execution; requests never choose a
// binary, path, or argument.
type commandRunner func(ctx context.Context, bin string, args []string) ([]byte, error)

// Agent runs the HTTPS server.
type Agent struct {
	cfg            Config
	log            *slog.Logger
	started        time.Time
	nginxPath      string
	systemctlPath  string
	nginxInstalled bool

	// runFn is the command executor. Production always uses runCommand; tests
	// may replace it. nginxTimeout bounds each validation/reload command.
	runFn        commandRunner
	nginxTimeout time.Duration

	updateMu  sync.Mutex
	updateFn  func(context.Context, string) (string, error)
	restartCh chan struct{}

	deployMu sync.Mutex
}

// New builds an Agent, resolving the nginx/systemctl paths from a fixed
// whitelist. It does not accept paths from any request.
func New(cfg Config, log *slog.Logger) (*Agent, error) {
	if log == nil {
		log = slog.Default()
	}
	if cfg.CertDir == "" {
		return nil, fmt.Errorf("config: cert_dir is required")
	}
	if cfg.CertFile == "" || cfg.KeyFile == "" || cfg.ServerCAFile == "" {
		return nil, fmt.Errorf("config: mTLS identity (cert_file/key_file/server_ca_file) is required")
	}
	a := &Agent{cfg: cfg, log: log, started: time.Now(), restartCh: make(chan struct{}, 1)}
	a.updateFn = func(ctx context.Context, target string) (string, error) {
		return updater.UpdateTo(ctx, updater.ComponentAgent, Version, target)
	}
	a.nginxPath = resolveFirst(whitelistedNginx)
	a.systemctlPath = resolveFirst(whitelistedSystemctl)
	a.nginxInstalled = a.nginxPath != ""
	a.runFn = runCommand
	a.nginxTimeout = defaultNginxTimeout
	return a, nil
}

func resolveFirst(vals []string) string {
	for _, v := range vals {
		if fi, err := os.Stat(v); err == nil && fi.Mode().IsRegular() {
			return v
		}
	}
	return ""
}

// TLSConfig returns the mTLS server configuration. It verifies that the
// presented client certificate is signed by the internal CA and rejects
// unauthenticated connections at the TLS layer.
func (a *Agent) TLSConfig() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(a.cfg.CertFile, a.cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load agent identity: %w", err)
	}
	caPEM, err := os.ReadFile(a.cfg.ServerCAFile)
	if err != nil {
		return nil, fmt.Errorf("load server ca: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("invalid server ca pem")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// RestartRequests is signaled after a verified binary update.
func (a *Agent) RestartRequests() <-chan struct{} { return a.restartCh }

// Handler returns the HTTP handler serving the agent API.
func (a *Agent) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+protocol.AgentAPIPrefix+"/health", a.handleHealth)
	mux.HandleFunc("POST "+protocol.AgentAPIPrefix+"/deploy", a.handleDeploy)
	mux.HandleFunc("POST "+protocol.AgentAPIPrefix+"/update", a.handleUpdate)
	return mux
}

func (a *Agent) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, protocol.HealthResponse{
		AgentID: a.cfg.AgentID, Version: Version,
		GOOS: runtime.GOOS, GOARCH: runtime.GOARCH,
		UptimeSeconds: int64(time.Since(a.started).Seconds()), NginxInstalled: a.nginxInstalled,
	})
}

// handleUpdate accepts only a target version. The repository, URL, asset,
// executable path and restart behavior are fixed inside the Agent/updater.
func (a *Agent) handleUpdate(w http.ResponseWriter, r *http.Request) {
	if !a.updateMu.TryLock() {
		w.WriteHeader(http.StatusConflict)
		writeJSON(w, protocol.UpdateResponse{
			AgentID: a.cfg.AgentID, CurrentVersion: Version,
			Error: "another update is already running",
		})
		return
	}
	defer a.updateMu.Unlock()

	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	var req protocol.UpdateRequest
	if err := decodeStrictJSON(r, &req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, protocol.UpdateResponse{AgentID: a.cfg.AgentID, CurrentVersion: Version, Error: err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()
	target, err := a.updateFn(ctx, req.Version)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, protocol.UpdateResponse{
			AgentID: a.cfg.AgentID, CurrentVersion: Version,
			TargetVersion: req.Version, Error: err.Error(),
		})
		return
	}
	writeJSON(w, protocol.UpdateResponse{
		Success: true, AgentID: a.cfg.AgentID, CurrentVersion: Version,
		TargetVersion: target, Restarting: true,
	})
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
	select {
	case a.restartCh <- struct{}{}:
	default:
	}
}

const defaultNginxTimeout = 20 * time.Second

// handleDeploy validates the request, installs the certificate version, and
// reloads nginx if installed. Certificate installs on one agent are serialized
// so two certificates cannot overlap nginx reloads.
func (a *Agent) handleDeploy(w http.ResponseWriter, r *http.Request) {
	var req protocol.DeployRequest
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, protocol.DeployResponse{Success: false, NginxStatus: "unknown", Error: "invalid request: " + err.Error(), Log: "invalid request: " + err.Error()})
		return
	}
	if !safeDomain.MatchString(req.RootDomain) {
		writeJSON(w, protocol.DeployResponse{Success: false, NginxStatus: "unknown", Error: "invalid root domain", Log: "invalid root domain"})
		return
	}
	a.deployMu.Lock()
	defer a.deployMu.Unlock()
	resp := a.deploy(req)
	writeJSON(w, resp)
}

// deploy installs the certificate, verifying it first, then atomically
// swapping files and reloading nginx. It returns a never-nil response.
func (a *Agent) deploy(req protocol.DeployRequest) (resp protocol.DeployResponse) {
	var logBuf strings.Builder
	logf := func(format string, args ...any) {
		if logBuf.Len() > 0 {
			logBuf.WriteByte('\n')
		}
		fmt.Fprintf(&logBuf, format, args...)
	}
	resp.AgentID = a.cfg.AgentID
	defer func() {
		resp.Log = logBuf.String()
	}()

	logf("verify certificate %s version %s", req.RootDomain, req.VersionID)
	if err := verifyCertMaterial(req); err != nil {
		resp.NginxStatus = "unknown"
		resp.Error = err.Error()
		logf("ERROR: %s", err)
		return resp
	}

	dir := filepath.Join(a.cfg.CertDir, req.RootDomain)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		resp.NginxStatus = "unknown"
		resp.Error = "create cert dir: " + err.Error()
		logf("ERROR: %s", resp.Error)
		return resp
	}
	paths := certPaths(dir)

	logf("write staged files under %s", dir)
	if err := writeStagedFiles(paths, req); err != nil {
		cleanupErr := cleanupStaged(paths)
		resp.NginxStatus = "unknown"
		resp.Error = errorReport("stage certificate files", err, cleanupDetail(cleanupErr))
		logf("ERROR: %s", resp.Error)
		return resp
	}

	st := newSwapState(paths)
	logf("back up live certificate files")
	if err := backupLive(st); err != nil {
		discardErr := discardBackups(st)
		cleanupErr := cleanupStaged(paths)
		resp.NginxStatus = "unknown"
		resp.Error = errorReport("back up live certificate files", err,
			cleanupDetail(errors.Join(discardErr, cleanupErr)))
		logf("ERROR: %s", resp.Error)
		return resp
	}

	logf("promote staged certificate files")
	if err := promote(st); err != nil {
		rollbackErr := rollback(st)
		cleanupErr := cleanupStaged(paths)
		resp.NginxStatus = "unknown"
		resp.Error = errorReport("install certificate files", err,
			rollbackDetail(rollbackErr), cleanupDetail(cleanupErr))
		logf("ERROR: %s", resp.Error)
		return resp
	}

	if !a.nginxInstalled {
		if commitErr := commit(st); commitErr != nil {
			logf("WARNING: %s", commitErr)
		}
		resp.Success = true
		resp.NginxStatus = "not-found"
		logf("nginx: not-found")
		logf("deploy success")
		return resp
	}

	logf("validate nginx configuration")
	validateOut, err := a.validateNginx()
	if strings.TrimSpace(validateOut) != "" {
		logf("%s", strings.TrimSpace(validateOut))
	}
	if err != nil {
		rollbackErr := rollback(st)
		cleanupErr := cleanupStaged(paths)
		resp.NginxStatus = "failed"
		resp.Error = errorReport("nginx configuration validation failed", err,
			rollbackDetail(rollbackErr), cleanupDetail(cleanupErr))
		logf("ERROR: %s", resp.Error)
		return resp
	}

	logf("reload nginx")
	reloadOut, err := a.reloadNginxWithTimeout()
	if strings.TrimSpace(reloadOut) != "" {
		logf("%s", strings.TrimSpace(reloadOut))
	}
	if err != nil {
		rollbackErr := rollback(st)
		cleanupErr := cleanupStaged(paths)
		recoveryText := ""
		if rollbackErr == nil {
			logf("attempt service recovery after reload failure")
			recoveryErr := a.recoverNginx(logf)
			recoveryText = recoveryDetail(recoveryErr)
		} else {
			logf("ERROR: rollback failed; service state is uncertain; skipping service recovery to avoid loading mixed files")
			recoveryText = "service state uncertain: recovery skipped after rollback failure"
		}
		resp.NginxStatus = "failed"
		resp.Error = errorReport("nginx reload failed", err,
			rollbackDetail(rollbackErr), recoveryText, cleanupDetail(cleanupErr))
		logf("ERROR: %s", resp.Error)
		return resp
	}

	if commitErr := commit(st); commitErr != nil {
		logf("WARNING: %s", commitErr)
	}
	resp.Success = true
	resp.NginxStatus = "ok"
	logf("nginx: ok")
	logf("deploy success")
	return resp
}

// recoverNginx re-validates and reloads the restored (old) files after a
// failed reload. It uses fresh, independent command contexts so a timeout in
// the original attempt cannot abort recovery.
func (a *Agent) recoverNginx(logf func(string, ...any)) error {
	validateOut, err := a.validateNginx()
	if strings.TrimSpace(validateOut) != "" {
		logf("%s", strings.TrimSpace(validateOut))
	}
	if err != nil {
		return fmt.Errorf("post-rollback validation: %w", err)
	}
	reloadOut, err := a.reloadNginxWithTimeout()
	if strings.TrimSpace(reloadOut) != "" {
		logf("%s", strings.TrimSpace(reloadOut))
	}
	if err != nil {
		return fmt.Errorf("post-rollback reload: %w", err)
	}
	return nil
}

func errorReport(original string, originalErr error, details ...string) string {
	parts := []string{fmt.Sprintf("%s: %v", original, originalErr)}
	for _, d := range details {
		if d != "" {
			parts = append(parts, d)
		}
	}
	return strings.Join(parts, "; ")
}

func rollbackDetail(err error) string {
	if err != nil {
		return "rollback failed: " + err.Error()
	}
	return "rollback: ok"
}

func recoveryDetail(err error) string {
	if err != nil {
		return "recovery failed: " + err.Error()
	}
	return "recovery: ok"
}

func cleanupDetail(err error) string {
	if err != nil {
		return "cleanup failed: " + err.Error()
	}
	return ""
}

// --- Fixed, non-parametrised command execution ---

func (a *Agent) nginxContext() (context.Context, context.CancelFunc) {
	timeout := a.nginxTimeout
	if timeout <= 0 {
		timeout = defaultNginxTimeout
	}
	return context.WithTimeout(context.Background(), timeout)
}

// validateNginx runs the hard-coded <nginx> -t. No value from a request ever
// reaches argv.
func (a *Agent) validateNginx() (string, error) {
	ctx, cancel := a.nginxContext()
	defer cancel()
	return a.checkNginx(ctx)
}

// checkNginx runs the hard-coded <nginx> -t.
func (a *Agent) checkNginx(ctx context.Context) (string, error) {
	return a.run(ctx, a.nginxPath, []string{"-t"})
}

// reloadNginxWithTimeout applies the freshly swapped certs with a bounded,
// independent context.
func (a *Agent) reloadNginxWithTimeout() (string, error) {
	ctx, cancel := a.nginxContext()
	defer cancel()
	return a.reloadNginx(ctx)
}

// reloadNginx applies the freshly swapped certs after checkNginx succeeded.
// It uses systemctl reload when available (never restart) and falls back to
// <nginx> -s reload. Both are fixed argv.
func (a *Agent) reloadNginx(ctx context.Context) (string, error) {
	if a.systemctlPath != "" {
		return a.run(ctx, a.systemctlPath, []string{"reload", "nginx"})
	}
	return a.run(ctx, a.nginxPath, []string{"-s", "reload"})
}

func (a *Agent) run(ctx context.Context, bin string, args []string) (string, error) {
	runner := a.runFn
	if runner == nil {
		runner = runCommand
	}
	out, err := runner(ctx, bin, args)
	text := truncate(string(out), 2048)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			if text == "" {
				text = ctxErr.Error()
			}
			a.log.Error("agent command aborted", "cmd", bin, "args", strings.Join(args, " "), "err", ctxErr, "out", text)
			return text, fmt.Errorf("%s %s %s: %w", bin, strings.Join(args, " "), contextStatus(ctxErr), ctxErr)
		}
		a.log.Error("agent command failed", "cmd", bin, "args", strings.Join(args, " "), "err", err, "out", text)
		if text == "" {
			text = err.Error()
		}
		return text, fmt.Errorf("%s %s failed: %s", bin, strings.Join(args, " "), text)
	}
	return text, nil
}

func contextStatus(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timed out"
	case errors.Is(err, context.Canceled):
		return "canceled"
	default:
		return "aborted"
	}
}
