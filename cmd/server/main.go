// Command server runs the oh-my-acme central service. It reads config.json
// (written by install.sh), opens the JSON store, bootstraps the internal PKI,
// starts the renewal scheduler, and serves the mTLS control port plus the
// (HTTP) Web UI.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Flyinsky2004/oh-my-acme/internal/server"
	"github.com/Flyinsky2004/oh-my-acme/internal/store"
)

func main() {
	var (
		configPath = flag.String("config", "/opt/oh-my-acme-server/config.json", "path to config.json")
		logLevel   = flag.String("log-level", "info", "log level: debug|info|warn|error")
	)
	flag.Parse()

	log := newLogger(*logLevel)

	if err := run(context.Background(), *configPath, log); err != nil {
		if errors.Is(err, server.ErrRestart) {
			os.Exit(75)
		}
		log.Error("server exited", "err", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, configPath string, log *slog.Logger) error {
	cfg, err := server.LoadConfigFile(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if cfg.WebListen == "" {
		cfg.WebListen = "127.0.0.1"
	}
	if cfg.WebPort == 0 {
		cfg.WebPort = 8080
	}
	if cfg.ControlListen == "" {
		cfg.ControlListen = "0.0.0.0"
	}
	if cfg.ControlPort == 0 {
		cfg.ControlPort = 9444
	}
	if cfg.DataDir == "" {
		cfg.DataDir = "/opt/oh-my-acme-server/data"
	}
	if cfg.PKIDir == "" {
		cfg.PKIDir = "/opt/oh-my-acme-server/pki"
	}
	if cfg.LogDir == "" {
		cfg.LogDir = "/opt/oh-my-acme-server/logs"
	}

	// Store (state.json + cert blobs).
	st, err := store.Open(cfg.DataDir)
	if err != nil {
		return err
	}

	// Internal PKI (CA + server identities).
	ca, srvID, cliID, err := server.EnsurePKI(cfg.PKIDir)
	if err != nil {
		return err
	}

	srv, err := server.New(cfg, log, st, ca, cliID, srvID)
	if err != nil {
		return err
	}

	// Print the one-time setup token so the admin can initialise the password.
	if token, terr := srv.InitialSetupToken(); terr == nil && token != "" {
		log.Warn("first-run setup: open the web UI and use this setup token (10 min), then clear it", "setup_token", token)
	} else if terr != nil {
		return terr
	}

	web, err := server.NewWeb(srv)
	if err != nil {
		return err
	}

	// Renewal scheduler interval.
	interval := time.Hour
	if renewCheck := st.State().Config.RenewCheckInterval; renewCheck != "" {
		if d, perr := time.ParseDuration(renewCheck); perr == nil && d > 0 {
			interval = d
		}
	}
	go srv.Scheduler(srv.Context(), interval, log)

	signalCtx, stopSignals := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stopSignals()

	errs := make(chan error, 2)
	go func() { errs <- srv.ListenAndServeWeb(web.Handler()) }()
	go func() { errs <- srv.ListenAndServeControl(srv.ControlHandler()) }()

	log.Info("oh-my-acme server started",
		"web", fmt.Sprintf("%s:%d", cfg.WebListen, cfg.WebPort),
		"control", fmt.Sprintf("%s:%d", cfg.ControlListen, cfg.ControlPort))

	restart := false
	select {
	case <-signalCtx.Done():
		log.Info("shutting down")
	case <-srv.RestartRequests():
		restart = true
		log.Info("restarting after update")
	case err := <-errs:
		return err
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Error("shutdown failed", "err", err)
	}
	if restart {
		return server.ErrRestart
	}
	return nil
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
