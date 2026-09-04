package server

import (
	"html/template"
	"strings"
	"testing"

	"github.com/Flyinsky2004/oh-my-acme/internal/domain"
	"github.com/Flyinsky2004/oh-my-acme/internal/store"
)

func TestUpdateCertificateReplacesTargetAgents(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	seedIssueState(t, st)
	if err := st.WithState(true, func(s *domain.State) error {
		s.Agents["agent1"] = &domain.Agent{ID: "agent1", Name: "a1", Address: "10.0.0.1", Port: 9123}
		s.Agents["agent2"] = &domain.Agent{ID: "agent2", Name: "a2", Address: "10.0.0.2", Port: 9123}
		s.Certificates["cert1"].TargetAgents = []string{"agent1"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	srv := &Server{st: st}
	if err := srv.UpdateCertificate("cert1", "example.com", "cred1", "ca1", domain.KeyTypeRSA2048, false, []string{"agent2"}); err != nil {
		t.Fatalf("update: %v", err)
	}

	got := st.State().Certificates["cert1"]
	if got.KeyType != domain.KeyTypeRSA2048 {
		t.Fatalf("key_type = %s", got.KeyType)
	}
	if got.Enabled {
		t.Fatal("enabled should be false")
	}
	if len(got.TargetAgents) != 1 || got.TargetAgents[0] != "agent2" {
		t.Fatalf("target_agents = %v", got.TargetAgents)
	}
}

func TestUpdateCertificateRejectsRunning(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	seedIssueState(t, st)
	if err := st.WithState(true, func(s *domain.State) error {
		s.Certificates["cert1"].IssueStatus = domain.StatusRunning
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	srv := &Server{st: st}
	if err := srv.UpdateCertificate("cert1", "example.com", "cred1", "ca1", "", true, nil); err == nil {
		t.Fatal("expected error while certificate is running")
	}
}

func TestDeleteCertificateCleansStateTasksAndDisk(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	seedIssueState(t, st)
	if err := st.WithState(true, func(s *domain.State) error {
		s.Tasks["task1"] = &domain.Task{ID: "task1", Type: taskTypeIssue, CertID: "cert1", Status: domain.StatusSuccess}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	v := domain.CertificateVersion{ID: "v1"}
	v, err = st.WriteCertVersion("cert1", v, []byte("cert"), []byte("ca"), []byte("full"), []byte("key"))
	if err != nil {
		t.Fatal(err)
	}

	srv := &Server{st: st}
	if err := srv.DeleteCertificate("cert1"); err != nil {
		t.Fatalf("delete: %v", err)
	}

	s := st.State()
	if s.Certificates["cert1"] != nil {
		t.Fatal("certificate still present in state")
	}
	if s.Tasks["task1"] != nil {
		t.Fatal("task not cleaned up")
	}
	if _, err := st.ReadFile(v.CertFile); err == nil {
		t.Fatal("cert files still present on disk")
	}
}

func TestDeleteCertificateRejectsRunning(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	seedIssueState(t, st)
	if err := st.WithState(true, func(s *domain.State) error {
		s.Certificates["cert1"].IssueStatus = domain.StatusRunning
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	srv := &Server{st: st}
	if err := srv.DeleteCertificate("cert1"); err == nil {
		t.Fatal("expected error while certificate is running")
	}
	if st.State().Certificates["cert1"] == nil {
		t.Fatal("certificate should not have been removed")
	}
}

func TestCertificateFormRendersNewAndEdit(t *testing.T) {
	tmpl, err := template.ParseFS(templatesFS, "web/templates/*.html")
	if err != nil {
		t.Fatal(err)
	}

	newForm := certificateForm{
		Credentials: []credOption{{ID: "cred1", Name: "CF"}},
		CAs:         []caView{{ID: "ca1", Name: "LE", Default: true}},
		Agents:      []agentView{{ID: "a1", Name: "one", Address: "1.1.1.1"}},
		Selected:    map[string]bool{},
	}
	var newOut strings.Builder
	if err := tmpl.ExecuteTemplate(&newOut, "certnew", newForm); err != nil {
		t.Fatalf("render new: %v", err)
	}
	if !strings.Contains(newOut.String(), `action="/certificates"`) {
		t.Fatalf("new form posts wrong action: %s", newOut.String())
	}

	editForm := certificateForm{
		Edit: true, ID: "cert1", RootDomain: "example.com",
		CredentialID: "cred1", ACMEID: "ca1", KeyType: "ec-384", Enabled: true,
		Credentials: []credOption{{ID: "cred1", Name: "CF"}},
		CAs:         []caView{{ID: "ca1", Name: "LE", Default: true}},
		Agents:      []agentView{{ID: "a1", Name: "one", Address: "1.1.1.1"}},
		Selected:    map[string]bool{"a1": true},
	}
	var editOut strings.Builder
	if err := tmpl.ExecuteTemplate(&editOut, "certnew", editForm); err != nil {
		t.Fatalf("render edit: %v", err)
	}
	got := editOut.String()
	if !strings.Contains(got, `action="/certificates/cert1"`) {
		t.Fatalf("edit form posts wrong action: %s", got)
	}
	if !strings.Contains(got, `value="example.com"`) {
		t.Fatalf("edit form missing root domain: %s", got)
	}
	if !strings.Contains(got, `value="ec-384" selected`) {
		t.Fatalf("edit form missing key type selection: %s", got)
	}
	if !strings.Contains(got, `value="a1" selected`) {
		t.Fatalf("edit form missing agent selection: %s", got)
	}
}
