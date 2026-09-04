package server

import (
	"strings"
	"testing"

	"github.com/Flyinsky2004/oh-my-acme/internal/domain"
	"github.com/Flyinsky2004/oh-my-acme/internal/store"
)

func TestAgentInstallCommandUsesConfiguredHost(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := st.WithState(true, func(s *domain.State) error {
		s.Config.ServerHost = "203.0.113.1"
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	srv := &Server{cfg: Config{ControlPort: 9444}, st: st}
	cmd := srv.AgentInstallCommand("agent1", "tok")
	if !strings.Contains(cmd, "-server 'https://203.0.113.1:9444'") {
		t.Fatalf("install command does not use configured host: %s", cmd)
	}
}

func TestAgentInstallCommandFallsBackWhenHostEmpty(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	srv := &Server{cfg: Config{ControlPort: 9444}, st: st}
	cmd := srv.AgentInstallCommand("agent1", "tok")
	if !strings.Contains(cmd, "-server 'https://") {
		t.Fatalf("install command missing -server arg on fallback: %s", cmd)
	}
}
