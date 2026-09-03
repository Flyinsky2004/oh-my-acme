// Package agent is the on-machine certificate deployment agent. It exposes a
// small mTLS HTTP API through which the server pushes certificate versions.
// The agent writes PEM files into a fixed directory and, if nginx is present
// and already configured to reference those paths, runs a validation +
// reload. It executes no arbitrary commands: the only programs ever launched
// are a hard-coded nginx "-t" and "systemctl reload nginx".
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

// Agent runs the HTTPS server.
type Agent struct {
	cfg            Config
	log            *slog.Logger
	started        time.Time
	nginxPath      string
	systemctlPath  string
	nginxInstalled bool

	updateMu  sync.Mutex
	updateFn  func(context.Context, string) (string, error)
	restartCh chan struct{}
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

// handleDeploy validates the request, installs the certificate version, and
// reloads nginx if installed.
func (a *Agent) handleDeploy(w http.ResponseWriter, r *http.Request) {
	var req protocol.DeployRequest
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, protocol.DeployResponse{Success: false, NginxStatus: "unknown", Error: "invalid request: " + err.Error()})
		return
	}
	if !safeDomain.MatchString(req.RootDomain) {
		writeJSON(w, protocol.DeployResponse{Success: false, NginxStatus: "unknown", Error: "invalid root domain"})
		return
	}
	resp := a.deploy(r, req)
	writeJSON(w, resp)
}

// deploy installs the certificate, verifying it first, then atomically
// swapping files and reloading nginx. It returns a never-nil response.
func (a *Agent) deploy(r *http.Request, req protocol.DeployRequest) protocol.DeployResponse {
	resp := protocol.DeployResponse{AgentID: a.cfg.AgentID}

	// Validate the material before touching any live file.
	if err := verifyCertMaterial(req); err != nil {
		resp.NginxStatus = "unknown"
		resp.Error = err.Error()
		return resp
	}

	dir := filepath.Join(a.cfg.CertDir, req.RootDomain)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		resp.NginxStatus = "unknown"
		resp.Error = "create cert dir: " + err.Error()
		return resp
	}
	paths := certPaths(dir)

	// Stage 1: write .new files.
	if err := writeNewFiles(paths, req); err != nil {
		cleanupStaged(paths)
		resp.NginxStatus = "unknown"
		resp.Error = err.Error()
		return resp
	}

	// Stage 2: back up live files, then swap .new into place.
	if err := swapLive(paths); err != nil {
		rollback(paths)
		cleanupStaged(paths)
		resp.NginxStatus = "unknown"
		resp.Error = err.Error()
		return resp
	}

	// Stage 3: nginx check + reload when installed. Roll back on failure so a
	// bad certificate never leaves the webserver in a broken state.
	if a.nginxInstalled {
		if err := a.checkNginx(r); err != nil {
			rollback(paths)
			cleanupStaged(paths)
			resp.NginxStatus = "failed"
			resp.Error = err.Error()
			return resp
		}
		if err := a.reloadNginx(r); err != nil {
			rollback(paths)
			cleanupStaged(paths)
			resp.NginxStatus = "failed"
			resp.Error = err.Error()
			return resp
		}
		resp.NginxStatus = "ok"
	} else {
		resp.NginxStatus = "not-found"
	}

	removeBackups(paths)
	resp.Success = true
	return resp
}

// --- Fixed, non-parametrised command execution ---

// checkNginx runs the hard-coded <nginx> -t. No value from a request ever
// reaches argv.
func (a *Agent) checkNginx(r *http.Request) error {
	return a.run(r, a.nginxPath, []string{"-t"})
}

// reloadNginx runs the hard-coded <systemctl> reload nginx, falling back to
// <nginx> -s reload when systemctl is missing.
func (a *Agent) reloadNginx(r *http.Request) error {
	if a.systemctlPath != "" {
		if err := a.run(r, a.systemctlPath, []string{"reload", "nginx"}); err == nil {
			return nil
		}
	}
	return a.run(r, a.nginxPath, []string{"-s", "reload"})
}

func (a *Agent) run(r *http.Request, bin string, args []string) error {
	out, err := runCommand(r.Context(), bin, args)
	if err != nil {
		a.log.Error("agent command failed", "cmd", bin, "err", err)
		return fmt.Errorf("%s %s failed: %s", bin, strings.Join(args, " "), truncate(string(out), 512))
	}
	return nil
}
