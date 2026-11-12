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

func newInstallCommandTestServer(t *testing.T, host string) *Server {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := st.WithState(true, func(s *domain.State) error {
		s.Config.ServerHost = host
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return &Server{cfg: Config{ControlPort: 9444}, st: st, serverLeafFP: "SHA256:" + strings.Repeat("a", 64)}
}

func TestAgentInstallCommandWithSudoOnlyDiffersByPrefix(t *testing.T) {
	srv := newInstallCommandTestServer(t, "203.0.113.1")

	withSudo := srv.AgentInstallCommandWithSudo("agent1", "tok", true)
	withoutSudo := srv.AgentInstallCommandWithSudo("agent1", "tok", false)

	if !strings.HasPrefix(withSudo, "sudo bash -c ") {
		t.Fatalf("sudo command prefix = %q", withSudo[:min(len(withSudo), 40)])
	}
	if !strings.HasPrefix(withoutSudo, "bash -c ") {
		t.Fatalf("non-sudo command prefix = %q", withoutSudo[:min(len(withoutSudo), 40)])
	}
	if strings.HasPrefix(withoutSudo, "sudo ") {
		t.Fatal("non-sudo command still starts with sudo")
	}
	if got := strings.TrimPrefix(withSudo, "sudo "); got != withoutSudo {
		t.Fatalf("commands differ by more than the sudo prefix:\n sudo: %s\n  raw: %s", withSudo, withoutSudo)
	}
	// The legacy entry point must keep elevating.
	if legacy := srv.AgentInstallCommand("agent1", "tok"); legacy != withSudo {
		t.Fatal("AgentInstallCommand no longer matches the sudo variant")
	}
	if !strings.HasPrefix(srv.AgentInstallCommand("agent1", "tok"), "sudo bash -c ") {
		t.Fatal("legacy install command lost its sudo prefix")
	}
}

func TestAgentInstallCommandWithSudoQuotesHostileArguments(t *testing.T) {
	host := "evil.example'; touch /tmp/pwned; echo '"
	srv := newInstallCommandTestServer(t, host)
	name := "节点 ' \" \\ \n$(touch should-not-exist)"
	token := "tok ' \" \\ \n`false`"

	for _, includeSudo := range []bool{true, false} {
		cmd := srv.AgentInstallCommandWithSudo(name, token, includeSudo)
		if !strings.Contains(cmd, shellQuote(name)) {
			t.Fatalf("includeSudo=%v: name is not shell-quoted: %s", includeSudo, cmd)
		}
		if !strings.Contains(cmd, shellQuote(token)) {
			t.Fatalf("includeSudo=%v: token is not shell-quoted: %s", includeSudo, cmd)
		}
		// A single quote in the host must be escaped inside the quoted control
		// URL, so the raw hostile host never appears verbatim.
		if strings.Contains(cmd, host) {
			t.Fatalf("includeSudo=%v: raw host appears unquoted: %s", includeSudo, cmd)
		}
		if !strings.Contains(cmd, "-ca-fingerprint "+shellQuote(srv.serverLeafFP)) {
			t.Fatalf("includeSudo=%v: fingerprint is not shell-quoted", includeSudo)
		}
	}
}
