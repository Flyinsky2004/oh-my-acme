package server

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Flyinsky2004/oh-my-acme/internal/domain"
	"github.com/Flyinsky2004/oh-my-acme/internal/store"
)

func TestClaimIssueIsIdempotent(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	seedIssueState(t, st)
	srv := &Server{st: st}

	_, first, started, err := srv.claimIssue("cert1", taskTypeIssue)
	if err != nil || !started || first == nil {
		t.Fatalf("first claim: task=%v started=%v err=%v", first, started, err)
	}
	_, second, started, err := srv.claimIssue("cert1", taskTypeRenew)
	if err != nil || started || second == nil {
		t.Fatalf("duplicate claim: task=%v started=%v err=%v", second, started, err)
	}
	if second.ID != first.ID {
		t.Fatalf("duplicate returned task %q, want %q", second.ID, first.ID)
	}
}

func TestEnsureDefaultsRecoversInterruptedIssue(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	seedIssueState(t, st)
	if err := st.WithState(true, func(s *domain.State) error {
		s.Tasks["task1"] = &domain.Task{ID: "task1", Type: taskTypeIssue, CertID: "cert1", Status: domain.StatusRunning}
		s.Certificates["cert1"].IssueStatus = domain.StatusRunning
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	(&Server{st: st}).ensureDefaults()
	got := st.State()
	if got.Tasks["task1"].Status != domain.StatusFailed || got.Tasks["task1"].FinishedAt.IsZero() {
		t.Fatalf("task not recovered: %+v", got.Tasks["task1"])
	}
	if got.Certificates["cert1"].IssueStatus != domain.StatusFailed {
		t.Fatalf("certificate status = %s", got.Certificates["cert1"].IssueStatus)
	}
}

func TestEnsureDefaultsRecoversInterruptedDeploy(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	seedIssueState(t, st)
	if err := st.WithState(true, func(s *domain.State) error {
		s.Certificates["cert1"].Current = &domain.CertificateVersion{ID: "v1"}
		s.Certificates["cert1"].DeployStatus = domain.StatusRunning
		s.Certificates["cert1"].TargetAgents = []string{"agent1"}
		s.Certificates["cert1"].Deploys = map[string]*domain.AgentDeployState{
			"agent1": {AgentID: "agent1", Status: domain.StatusRunning},
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	(&Server{st: st}).ensureDefaults()
	got := st.State().Certificates["cert1"]
	if got.DeployStatus != domain.StatusFailed {
		t.Fatalf("certificate deploy status = %s", got.DeployStatus)
	}
	if d := got.Deploys["agent1"]; d == nil || d.Status != domain.StatusFailed || d.Error != "interrupted by server restart" {
		t.Fatalf("agent deploy not recovered: %+v", d)
	}
}

func TestClaimIssueBlockedWhileDeploying(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	seedIssueState(t, st)
	if err := st.WithState(true, func(s *domain.State) error {
		s.Certificates["cert1"].DeployStatus = domain.StatusRunning
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	_, task, started, err := (&Server{st: st}).claimIssue("cert1", taskTypeIssue)
	if !errors.Is(err, errCertDeploying) {
		t.Fatalf("claimIssue err = %v, want errCertDeploying", err)
	}
	if started || task != nil {
		t.Fatalf("claimIssue started=%v task=%v", started, task)
	}
}

func TestCertificateRowPollsOnlyWhileRunning(t *testing.T) {
	tmpl, err := parseWebTemplates()
	if err != nil {
		t.Fatal(err)
	}
	render := func(status domain.OperationStatus) string {
		cert := &domain.Certificate{ID: "cert1", RootDomain: "example.com", KeyType: domain.KeyTypeEC256, IssueStatus: status}
		var out strings.Builder
		if err := tmpl.ExecuteTemplate(&out, "certificate-row", makeCertificateRow(cert)); err != nil {
			t.Fatal(err)
		}
		return out.String()
	}
	if got := render(domain.StatusRunning); !strings.Contains(got, `hx-get="/certificates/cert1/row"`) || !strings.Contains(got, `hx-trigger="every 5s"`) {
		t.Fatalf("running row does not poll: %s", got)
	}
	if got := render(domain.StatusSuccess); strings.Contains(got, "hx-trigger") {
		t.Fatalf("terminal row still polls: %s", got)
	}
	var deployOut strings.Builder
	deployCert := &domain.Certificate{
		ID: "cert1", RootDomain: "example.com", KeyType: domain.KeyTypeEC256,
		Current: &domain.CertificateVersion{ID: "v1"}, DeployStatus: domain.StatusRunning,
	}
	if err := tmpl.ExecuteTemplate(&deployOut, "certificate-row", makeCertificateRow(deployCert)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(deployOut.String(), `hx-get="/certificates/cert1/row"`) || !strings.Contains(deployOut.String(), `hx-trigger="every 5s"`) {
		t.Fatalf("deploying row does not poll: %s", deployOut.String())
	}
}

func seedIssueState(t *testing.T, st *store.Store) {
	t.Helper()
	if err := st.WithState(true, func(s *domain.State) error {
		s.CAs["ca1"] = &domain.ACMECA{ID: "ca1", Enabled: true, DirectoryURL: "https://example.invalid/directory"}
		s.Credentials["cred1"] = &domain.CloudflareCredential{ID: "cred1", Enabled: true, Token: "token"}
		s.Certificates["cert1"] = &domain.Certificate{
			ID: "cert1", RootDomain: "example.com", SanDomains: []string{"example.com", "*.example.com"},
			ACMEID: "ca1", CredentialID: "cred1", KeyType: domain.KeyTypeEC256,
			IssueStatus: domain.StatusPending, CreatedAt: time.Now(),
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
