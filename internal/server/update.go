package server

import (
	"context"
	"fmt"
	"time"

	"github.com/Flyinsky2004/oh-my-acme/internal/domain"
	"github.com/Flyinsky2004/oh-my-acme/internal/updater"
)

// SelfUpdateState is the small in-memory status shown in Settings.
type SelfUpdateState struct {
	Status domain.OperationStatus
	Target string
	Error  string
}

// ServerVersions returns stable, compatible releases newer than the running
// Server version.
func (s *Server) ServerVersions(ctx context.Context) ([]string, error) {
	if Version == "" || Version == "dev" {
		return nil, fmt.Errorf("development build cannot self-update")
	}
	return updater.Available(ctx, updater.ComponentServer, Version)
}

// SelfUpdate returns the current in-memory update status.
func (s *Server) SelfUpdate() SelfUpdateState {
	s.selfUpdateMu.Lock()
	defer s.selfUpdateMu.Unlock()
	return SelfUpdateState{Status: s.selfUpdateStatus, Target: s.selfUpdateTarget, Error: s.selfUpdateError}
}

// StartSelfUpdate validates and installs one selected stable upgrade in the
// background. After the binary is atomically replaced, main is asked to exit
// and systemd restarts the fixed service command.
func (s *Server) StartSelfUpdate(target string) error {
	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	versions, err := s.ServerVersions(ctx)
	cancel()
	if err != nil {
		return err
	}
	if !containsString(versions, target) {
		return fmt.Errorf("version %q is not an eligible server upgrade", target)
	}

	s.selfUpdateMu.Lock()
	if s.selfUpdateStatus == domain.StatusRunning {
		s.selfUpdateMu.Unlock()
		return fmt.Errorf("server update is already running")
	}
	s.selfUpdateStatus = domain.StatusRunning
	s.selfUpdateTarget = target
	s.selfUpdateError = ""
	s.selfUpdateMu.Unlock()

	s.Go(func(parent context.Context) {
		ctx, cancel := context.WithTimeout(parent, 5*time.Minute)
		defer cancel()
		_, err := updater.UpdateTo(ctx, updater.ComponentServer, Version, target)
		s.selfUpdateMu.Lock()
		if err != nil {
			s.selfUpdateStatus = domain.StatusFailed
			s.selfUpdateError = err.Error()
			s.selfUpdateMu.Unlock()
			s.log.Error("server update failed", "target", target, "err", err)
			return
		}
		s.selfUpdateStatus = domain.StatusSuccess
		s.selfUpdateError = ""
		s.selfUpdateMu.Unlock()
		s.RequestRestart()
	})
	return nil
}
