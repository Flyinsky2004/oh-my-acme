// Package server is the oh-my-acme central service. It issues and renews
// wildcard certificates via ACME (DNS-01 on Cloudflare), persists state in
// JSON, and actively pushes certificate versions to registered agents over
// mTLS. It exposes two HTTP surfaces: the Web UI (HTTP, behind the user's own
// reverse proxy) and a control port (HTTPS, internal CA + mTLS) used by
// agents to register.
package server

import (
	"context"
	"crypto/cipher"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Flyinsky2004/oh-my-acme/internal/acme"
	"github.com/Flyinsky2004/oh-my-acme/internal/domain"
	"github.com/Flyinsky2004/oh-my-acme/internal/pki"
	"github.com/Flyinsky2004/oh-my-acme/internal/store"
)

// setupPending reports whether the single-admin site has not yet been
// initialised (no password set).
func (s *Server) setupPending() bool {
	return !s.st.State().Admin.SetupTokenUsed
}

// AgentInstallCommand builds the command line an admin runs on a target
// machine to install and register a new agent. It keeps the historical
// behaviour of elevating with sudo; callers that already run as root can use
// AgentInstallCommandWithSudo(..., false).
func (s *Server) AgentInstallCommand(name, token string) string {
	return s.AgentInstallCommandWithSudo(name, token, true)
}

// AgentInstallCommandWithSudo builds the install command. includeSudo only
// changes the outermost elevation prefix ("sudo bash -c" vs "bash -c"); the
// bootstrap script, pinned download sources, checksum verification, private
// temporary directory and every quoted argument are identical in both
// variants. A released server downloads the installer from its own immutable
// GitHub Release and pins the Agent to the same version, avoiding protocol
// drift. Development builds use main/latest.
func (s *Server) AgentInstallCommandWithSudo(name, token string, includeSudo bool) string {
	host := strings.TrimSpace(s.st.State().Config.ServerHost)
	if host == "" {
		// Interface enumeration can be unavailable in a restricted environment.
		// Keep the loopback fallback even in that case; an administrator may
		// replace it with the reachable address before running the command.
		host = "127.0.0.1"
		if ips, err := serverIPs(); err == nil && len(ips) > 0 {
			host = ips[0].String()
		}
	}
	control := "https://" + net.JoinHostPort(strings.Trim(host, "[]"), strconv.Itoa(s.cfg.ControlPort))
	installerURL := "https://raw.githubusercontent.com/Flyinsky2004/oh-my-acme/main/agent/install.sh"
	checksumURL := ""
	versionArg := ""
	if Version != "" && Version != "dev" {
		installerURL = fmt.Sprintf("https://github.com/Flyinsky2004/oh-my-acme/releases/download/%s/install-agent.sh", Version)
		checksumURL = fmt.Sprintf("https://github.com/Flyinsky2004/oh-my-acme/releases/download/%s/checksums.txt", Version)
		versionArg = " -version " + shellQuote(Version)
	}
	// Elevate before creating or downloading the installer. A root-owned 0700
	// directory prevents an unprivileged local user from replacing a downloaded
	// script between verification and execution. Release checksums detect
	// corruption; they are not signatures independent of the release account.
	bootstrap := `set -eu
umask 077
tmp=$(mktemp -d /tmp/oh-my-acme-agent.XXXXXXXX)
trap 'rm -rf -- "$tmp"' EXIT
trap 'exit 1' HUP INT TERM
curl --proto '=https' --proto-redir '=https' -fsSL -o "$tmp/install.sh" "$1"
if [ -n "$2" ]; then
  curl --proto '=https' --proto-redir '=https' -fsSL -o "$tmp/checksums.txt" "$2"
  expected=$(awk '$2 == "install-agent.sh" {print $1}' "$tmp/checksums.txt")
  actual=$(sha256sum "$tmp/install.sh")
  actual=${actual%% *}
  [ "${#expected}" -eq 64 ] && [ "$expected" = "$actual" ] || { echo 'installer checksum mismatch' >&2; exit 1; }
fi
shift 2
bash "$tmp/install.sh" "$@"`
	elevation := "bash"
	if includeSudo {
		elevation = "sudo bash"
	}
	return fmt.Sprintf(
		"%s -c %s oh-my-acme-install %s %s -server %s -token %s -ca-fingerprint %s -name %s -port 9123%s",
		elevation, shellQuote(bootstrap), shellQuote(installerURL), shellQuote(checksumURL), shellQuote(control), shellQuote(token), shellQuote(s.serverLeafFP), shellQuote(name), versionArg,
	)
}

// shellQuote returns a POSIX-shell-safe single-quoted argument.
func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

// Version is set at build time via -ldflags.
var Version = "dev"

// ErrRestart asks main to exit with a non-zero code so systemd's fixed
// Restart=on-failure policy starts the newly installed binary.
var ErrRestart = errors.New("restart requested")

// builtinCAs are pre-seeded CA entries; the default is Let's Encrypt
// Production. Users may add arbitrary RFC 8555 directory URLs (no EAB).
const (
	caLetsEncryptProd = "https://acme-v02.api.letsencrypt.org/directory"
	caLetsEncryptTest = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

// Server wires the store, PKI and ACME service, exposes business operations
// and HTTP handlers.
type Server struct {
	twoFactorCipher cipher.AEAD
	cfg             Config
	log             *slog.Logger
	st              *store.Store
	ca              *pki.CA
	cliTLSCfg       *tls.Config     // client cert + CA used to connect to agents
	ctlTLSCert      tls.Certificate // control port server cert
	clientCert      *pki.KeyPair    // server push client identity

	acmeSvc      *acme.Service
	serverLeafFP string // SHA-256 of the server's TLS leaf cert (agent pin)
	tg           *TelegramController

	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	restartCh   chan struct{}
	webHTTP     *http.Server
	controlHTTP *http.Server

	selfUpdateMu     sync.Mutex
	selfUpdateStatus domain.OperationStatus
	selfUpdateTarget string
	selfUpdateError  string

	deployTimeout time.Duration
}

// StartOptions are the dependencies the server needs to boot.
type StartOptions struct {
	Config     Config
	Logger     *slog.Logger
	Store      *store.Store
	CA         *pki.CA
	ClientCert *pki.KeyPair
}

// New builds a Server from an already-open store and CA.
func New(cfg Config, log *slog.Logger, st *store.Store, ca *pki.CA, clientCert *pki.KeyPair, serverIdentity *pki.KeyPair) (*Server, error) {
	cliCert, err := clientCert.TLSCertificate()
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	cliTLS := &tls.Config{
		Certificates: []tls.Certificate{cliCert},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS12,
	}

	serverTLSCert, err := serverIdentity.TLSCertificate()
	if err != nil {
		return nil, err
	}

	lifecycleCtx, cancel := context.WithCancel(context.Background())
	s := &Server{
		cfg:          cfg,
		log:          log,
		st:           st,
		ca:           ca,
		cliTLSCfg:    cliTLS,
		ctlTLSCert:   serverTLSCert,
		clientCert:   clientCert,
		acmeSvc:      acme.New(log),
		serverLeafFP: serverIdentity.Fingerprint(),
		ctx:          lifecycleCtx,
		cancel:       cancel,
		restartCh:    make(chan struct{}, 1),
	}
	if err := s.initTwoFactorEncryption(); err != nil {
		cancel()
		return nil, err
	}
	s.ensureDefaults()
	s.tg = newTelegramController(s)
	return s, nil
}

// AcmeService exposes the ACME service for tests / handlers.
func (s *Server) AcmeService() *acme.Service { return s.acmeSvc }

// Store returns the underlying store.
func (s *Server) Store() *store.Store { return s.st }

// Context is canceled when the server is shutting down or restarting.
func (s *Server) Context() context.Context { return s.ctx }

// RestartRequests is signaled after a successful self-update.
func (s *Server) RestartRequests() <-chan struct{} { return s.restartCh }

// RequestRestart asks main to gracefully stop and exit under systemd.
func (s *Server) RequestRestart() {
	select {
	case s.restartCh <- struct{}{}:
	default:
	}
}

// TelegramReset reconciles the Telegram bot against the persisted config. It is
// called on startup and whenever the settings are saved, so enabling/disabling
// or changing the token takes effect without a full restart.
func (s *Server) TelegramReset() {
	if s.tg != nil {
		s.tg.Reconcile()
	}
}

// TelegramRuntimeStatus reports the sanitized state of the optional bot.
func (s *Server) TelegramRuntimeStatus() (status, message string) {
	if s.tg == nil {
		return "disabled", ""
	}
	return s.tg.runtimeStatus()
}

// Go starts lifecycle-bound background work tracked for shutdown.
func (s *Server) Go(fn func(context.Context)) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		fn(s.ctx)
	}()
}

// CircuitToAgent returns the connection timeout for agent pushes.
func (s *Server) agentDialTimeout() time.Duration {
	secs := s.st.State().Config.ServerConnectTimeoutSeconds
	if secs <= 0 {
		secs = 10
	}
	return time.Duration(secs) * time.Second
}

// ensureDefaults seeds built-in CAs and fills empty config fields on first run.
func (s *Server) ensureDefaults() {
	_ = s.st.WithState(true, func(st *domain.State) error {
		if st.Tasks == nil {
			st.Tasks = map[string]*domain.Task{}
		}
		interruptedAt := time.Now()
		for _, task := range st.Tasks {
			if task.Status == domain.StatusPending || task.Status == domain.StatusRunning {
				task.Status = domain.StatusFailed
				task.FinishedAt = interruptedAt
				task.Error = "interrupted by server restart"
				if cert := st.Certificates[task.CertID]; cert != nil {
					cert.IssueStatus = domain.StatusFailed
					cert.LastError = task.Error
				}
			}
		}
		for _, cert := range st.Certificates {
			if cert.IssueStatus == domain.StatusRunning {
				cert.IssueStatus = domain.StatusFailed
				cert.LastError = "interrupted by server restart"
			}
			if cert.DeployStatus == domain.StatusRunning {
				cert.DeployStatus = domain.StatusFailed
				for _, deploy := range cert.Deploys {
					if deploy != nil && deploy.Status == domain.StatusRunning {
						deploy.Status = domain.StatusFailed
						deploy.Error = "interrupted by server restart"
						if deploy.LastLog == "" {
							deploy.LastLog = deploy.Error
						}
					}
				}
			}
		}
		if st.Config.DefaultKeyType == "" {
			st.Config.DefaultKeyType = "ec-256"
		}
		if st.Config.RenewPreferenceDays <= 0 {
			st.Config.RenewPreferenceDays = 30
		}
		if st.Config.RenewCheckInterval == "" {
			st.Config.RenewCheckInterval = "24h"
		}
		if len(st.CAs) == 0 {
			prod := &domain.ACMECA{ID: "le-prod", Name: "Let's Encrypt (Production)", DirectoryURL: caLetsEncryptProd, Builtin: true, Enabled: true}
			stage := &domain.ACMECA{ID: "le-staging", Name: "Let's Encrypt (Staging)", DirectoryURL: caLetsEncryptTest, Builtin: true, Enabled: true}
			st.CAs["le-prod"] = prod
			st.CAs["le-staging"] = stage
			if st.Config.DefaultACMEID == "" {
				st.Config.DefaultACMEID = "le-prod"
			}
		}
		return nil
	})
}

// ControlTLSConfig returns the control port TLS config. Registration is the
// bootstrap step: at that point an agent has no identity yet, so a client
// certificate is requested but NOT required — authentication is the one-time
// token plus the server's own TLS identity being pinned by the agent. Any
// client cert that IS presented is verified against the internal CA. After
// registration the push direction is fully mutual (the server presents a
// client cert that the agent's own mTLS server verifies).
func (s *Server) ControlTLSConfig() (*tls.Config, error) {
	pool := x509.NewCertPool()
	pool.AddCert(s.ca.Cert)
	return &tls.Config{
		Certificates: []tls.Certificate{s.ctlTLSCert},
		ClientAuth:   tls.RequestClientCert,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// WebTLSConfig is nil: the Web UI is HTTP-only, TLS terminated by the user's
// reverse proxy.
func (s *Server) WebTLSConfig() *tls.Config { return nil }

// ListenAndServeWeb starts the Web UI HTTP server and blocks.
func (s *Server) ListenAndServeWeb(handler http.Handler) error {
	addr := net.JoinHostPort(s.cfg.WebListen, fmt.Sprintf("%d", s.cfg.WebPort))
	s.webHTTP = &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	s.log.Info("web ui listening", "addr", addr)
	return s.webHTTP.ListenAndServe()
}

// ListenAndServeControl starts the mTLS control server and blocks.
func (s *Server) ListenAndServeControl(handler http.Handler) error {
	addr := net.JoinHostPort(s.cfg.ControlListen, fmt.Sprintf("%d", s.cfg.ControlPort))
	tlsCfg, err := s.ControlTLSConfig()
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	ln = tls.NewListener(ln, tlsCfg)
	s.controlHTTP = &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	s.log.Info("control port listening", "addr", addr)
	return s.controlHTTP.Serve(ln)
}

// Shutdown cancels background work and gracefully stops both HTTP servers.
func (s *Server) Shutdown(ctx context.Context) error {
	s.cancel()
	var firstErr error
	if s.webHTTP != nil {
		if err := s.webHTTP.Shutdown(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			firstErr = err
		}
	}
	if s.controlHTTP != nil {
		if err := s.controlHTTP.Shutdown(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) && firstErr == nil {
			firstErr = err
		}
	}
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		if firstErr == nil {
			firstErr = ctx.Err()
		}
	}
	return firstErr
}
