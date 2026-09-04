// Command agent runs the oh-my-acme on-machine certificate deployment agent.
//
// It reads config.json (written by install.sh). On first start it performs a
// one-time registration against the server control port (using a one-time
// token + pinned CA fingerprint), then persists its mTLS identity and starts
// serving. Subsequent starts skip registration.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Flyinsky2004/oh-my-acme/internal/agent"
)

func main() {
	var (
		configPath = flag.String("config", "/opt/oh-my-acme-agent/config.json", "path to config.json")
		logLevel   = flag.String("log-level", "info", "log level: debug|info|warn|error")
	)
	flag.Parse()

	log := newLogger(*logLevel)
	log.Info("agent version", "version", agent.Version)

	if err := run(context.Background(), *configPath, log); err != nil {
		if errors.Is(err, agent.ErrRestart) {
			os.Exit(75)
		}
		log.Error("agent exited", "err", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, configPath string, log *slog.Logger) error {
	cfg, err := agent.LoadConfig(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	cfg.FillDefaults()

	// First-run registration.
	if cfg.AgentID == "" || !fileExists(cfg.CertFile) {
		if err := register(ctx, configPath, cfg); err != nil {
			return fmt.Errorf("registration failed: %w", err)
		}
		cfg, err = agent.LoadConfig(configPath)
		if err != nil {
			return err
		}
		cfg.FillDefaults()
	}
	if len(cfg.AllowedServerCIDRs) == 0 {
		resolveCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		allowed, resolveErr := agent.ServerCIDRsFromURL(resolveCtx, cfg.ServerURL)
		cancel()
		if resolveErr != nil {
			return fmt.Errorf("initialize Server IP allowlist: %w", resolveErr)
		}
		cfg.AllowedServerCIDRs = allowed
		if err := agent.SaveConfig(configPath, cfg); err != nil {
			return fmt.Errorf("persist Server IP allowlist: %w", err)
		}
		log.Warn("initialized Server IP allowlist from server_url", "allowed_server_cidrs", strings.Join(allowed, ","))
	}

	a, err := agent.New(cfg, log)
	if err != nil {
		return err
	}
	tlsCfg, err := a.TLSConfig()
	if err != nil {
		return err
	}

	addr := fmt.Sprintf("%s:%d", cfg.Listen, cfg.Port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	ln, err = agent.RestrictListener(ln, cfg.AllowedServerCIDRs, log)
	if err != nil {
		_ = ln.Close()
		return fmt.Errorf("configure Server IP allowlist: %w", err)
	}
	ln = tlsListener(ln, tlsCfg)

	srv := &http.Server{
		Handler:           a.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}

	// Run until SIGINT/SIGTERM.
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(ln) }()
	log.Info("agent listening", "addr", addr, "agent_id", cfg.AgentID)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	restart := false
	select {
	case s := <-sigCh:
		log.Info("shutting down", "signal", s.String())
	case <-a.RestartRequests():
		restart = true
		log.Info("restarting after update")
	case err := <-errCh:
		return err
	}
	shutCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutCtx); err != nil {
		return err
	}
	if restart {
		return agent.ErrRestart
	}
	return nil
}

// register performs the one-time registration: generate key+CSR, call the
// server control port, persist identity and clear the token.
func register(ctx context.Context, configPath string, cfg agent.Config) error {
	if cfg.ServerURL == "" {
		return fmt.Errorf("config: server_url is required for registration")
	}
	name := cfg.Name
	if name == "" {
		name = hostname()
	}
	keyPEM, csrPEM, err := agent.GenerateKeyAndCSR(name)
	if err != nil {
		return err
	}
	reg, err := agent.Register(ctx, cfg.ServerURL, cfg.Token, cfg.AgentID, name, cfg.Port, csrPEM, cfg.CAFingerprint)
	if err != nil {
		return err
	}
	cfg.AgentID = reg.AgentID
	cfg.Name = name
	cfg.Token = "" // one-time; clear it
	serverCIDR, err := agent.ExactServerCIDR(reg.ServerIP)
	if err != nil {
		return err
	}
	cfg.AllowedServerCIDRs = []string{serverCIDR}
	if err := agent.SaveIdentity(cfg, reg, keyPEM); err != nil {
		return err
	}
	return agent.SaveConfig(configPath, cfg)
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "agent"
	}
	return strings.TrimSpace(h)
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func newLogger(level string) *slog.Logger {
	var l slog.Level
	switch strings.ToLower(level) {
	case "debug":
		l = slog.LevelDebug
	case "warn":
		l = slog.LevelWarn
	case "error":
		l = slog.LevelError
	default:
		l = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: l}))
}

// tlsListener wraps a TCP listener with a TLS one.
func tlsListener(ln net.Listener, cfg *tls.Config) net.Listener {
	return tls.NewListener(ln, cfg)
}
