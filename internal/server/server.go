// Package server is the oh-my-acme central service. It issues and renews
// wildcard certificates via ACME (DNS-01 on Cloudflare), persists state in
// JSON, and actively pushes certificate versions to registered agents over
// mTLS. It exposes two HTTP surfaces: the Web UI (HTTP, behind the user's own
// reverse proxy) and a control port (HTTPS, internal CA + mTLS) used by
// agents to register.
package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
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
// machine to install and register a new agent. A released server downloads the
// installer from its own immutable GitHub Release and pins the Agent to the
// same version, avoiding protocol drift. Development builds use main/latest.
func (s *Server) AgentInstallCommand(name, token string) string {
	ips, err := serverIPs()
	if err != nil {
		return ""
	}
	host := "127.0.0.1"
	if len(ips) > 0 {
		host = ips[0].String()
	}
	control := fmt.Sprintf("https://%s:%d", host, s.cfg.ControlPort)
	installerURL := "https://raw.githubusercontent.com/Flyinsky2004/oh-my-acme/main/agent/install.sh"
	versionArg := ""
	if Version != "" && Version != "dev" {
		installerURL = fmt.Sprintf("https://github.com/Flyinsky2004/oh-my-acme/releases/download/%s/install-agent.sh", Version)
		versionArg = " -version " + shellQuote(Version)
	}
	return fmt.Sprintf(
		"curl -fsSL -o /tmp/oh-my-acme-agent-install.sh %s && sudo bash /tmp/oh-my-acme-agent-install.sh -server %s -token %s -ca-fingerprint %s -name %s -port 9123%s",
		shellQuote(installerURL), shellQuote(control), shellQuote(token), shellQuote(s.serverLeafFP), shellQuote(name), versionArg,
	)
}

// shellQuote returns a POSIX-shell-safe single-quoted argument.
func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

// Version is set at build time via -ldflags.
var Version = "dev"

// builtinCAs are pre-seeded CA entries; the default is Let's Encrypt
// Production. Users may add arbitrary RFC 8555 directory URLs (no EAB).
const (
	caLetsEncryptProd = "https://acme-v02.api.letsencrypt.org/directory"
	caLetsEncryptTest = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

// Server wires the store, PKI and ACME service, exposes business operations
// and HTTP handlers.
type Server struct {
	cfg        Config
	log        *slog.Logger
	st         *store.Store
	ca         *pki.CA
	cliTLSCfg  *tls.Config     // client cert + CA used to connect to agents
	ctlTLSCert tls.Certificate // control port server cert
	clientCert *pki.KeyPair    // server push client identity

	acmeSvc      *acme.Service
	serverLeafFP string // SHA-256 of the server's TLS leaf cert (agent pin)
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
	}
	s.ensureDefaults()
	return s, nil
}

// AcmeService exposes the ACME service for tests / handlers.
func (s *Server) AcmeService() *acme.Service { return s.acmeSvc }

// Store returns the underlying store.
func (s *Server) Store() *store.Store { return s.st }

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
	srv := &http.Server{Addr: addr, Handler: handler}
	s.log.Info("web ui listening", "addr", addr)
	return srv.ListenAndServe()
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
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	s.log.Info("control port listening", "addr", addr)
	return srv.Serve(ln)
}

// Shutdown gracefully stops both servers.
func (s *Server) Shutdown(ctx context.Context) error {
	return ctx.Err()
}
