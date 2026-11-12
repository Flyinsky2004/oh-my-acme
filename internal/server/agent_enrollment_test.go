package server

import (
	"errors"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/Flyinsky2004/oh-my-acme/internal/domain"
	"github.com/Flyinsky2004/oh-my-acme/internal/store"
)

// seedEnrollmentCertificate writes a certificate configuration directly into
// the store so enrollment tests can control its existing targets and deploy
// records.
func seedEnrollmentCertificate(t *testing.T, st *store.Store, id string, targets []string, deploys map[string]*domain.AgentDeployState) {
	t.Helper()
	if err := st.WithState(true, func(state *domain.State) error {
		state.Certificates[id] = &domain.Certificate{
			ID:           id,
			RootDomain:   id + ".example.com",
			SanDomains:   []string{id + ".example.com", "*." + id + ".example.com"},
			Enabled:      true,
			TargetAgents: append([]string(nil), targets...),
			Deploys:      deploys,
			IssueStatus:  domain.StatusSuccess,
			CreatedAt:    time.Now(),
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestCreateAgentTokenWithCertificatesDedupesSelection(t *testing.T) {
	srv, st, _ := newControlTestServer(t)
	seedEnrollmentCertificate(t, st, "cert-a", []string{"existing-a"}, nil)
	seedEnrollmentCertificate(t, st, "cert-b", []string{"existing-b"}, nil)

	token, agentID, err := srv.CreateAgentTokenWithCertificates("agent", []string{"cert-b", "cert-a", "cert-b", "cert-a"})
	if err != nil {
		t.Fatal(err)
	}
	state := st.State()
	rec := state.Tokens[token]
	if rec == nil {
		t.Fatal("token was not persisted")
	}
	if rec.AgentID != agentID {
		t.Fatalf("agent id = %q, want %q", rec.AgentID, agentID)
	}
	if got, want := rec.CertificateIDs, []string{"cert-b", "cert-a"}; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("certificate ids = %#v, want %#v", got, want)
	}
	if !rec.ExpiresAt.After(time.Now()) {
		t.Fatal("token is already expired")
	}
	// Minting a token must not bind anything yet.
	if got := state.Certificates["cert-a"].TargetAgents; len(got) != 1 || got[0] != "existing-a" {
		t.Fatalf("cert-a targets changed at mint time: %#v", got)
	}
	if got := state.Certificates["cert-b"].TargetAgents; len(got) != 1 || got[0] != "existing-b" {
		t.Fatalf("cert-b targets changed at mint time: %#v", got)
	}
}

func TestCreateAgentTokenWithCertificatesRejectsUnknownSelection(t *testing.T) {
	srv, st, _ := newControlTestServer(t)
	seedEnrollmentCertificate(t, st, "cert-a", nil, nil)

	before := st.State()
	_, _, err := srv.CreateAgentTokenWithCertificates("agent", []string{"cert-a", "missing"})
	if !errors.Is(err, errCertificateSelectionNotFound) {
		t.Fatalf("err = %v, want errCertificateSelectionNotFound", err)
	}
	after := st.State()
	if len(after.Tokens) != len(before.Tokens) {
		t.Fatalf("tokens = %d, want %d", len(after.Tokens), len(before.Tokens))
	}
	for token := range after.Tokens {
		if _, ok := before.Tokens[token]; !ok {
			t.Fatalf("partial token %q was written", token)
		}
	}
}

func TestCreateAgentTokenWithoutCertificatesKeepsLegacyBehaviour(t *testing.T) {
	srv, st, _ := newControlTestServer(t)
	token, _, err := srv.CreateAgentTokenWithCertificates("agent", nil)
	if err != nil {
		t.Fatal(err)
	}
	rec := st.State().Tokens[token]
	if rec == nil {
		t.Fatal("token was not persisted")
	}
	if len(rec.CertificateIDs) != 0 {
		t.Fatalf("certificate ids = %#v, want empty", rec.CertificateIDs)
	}
}

func TestRegisterBindsOnlySelectedCertificatesAndPreservesState(t *testing.T) {
	srv, st, _ := newControlTestServer(t)
	existingDeploy := &domain.AgentDeployState{
		AgentID: "existing-a", VersionID: "v1", Status: domain.StatusSuccess,
		LastSuccessAt: time.Now().Add(-time.Hour),
	}
	seedEnrollmentCertificate(t, st, "cert-a", []string{"existing-a"}, map[string]*domain.AgentDeployState{
		"existing-a": existingDeploy,
	})
	seedEnrollmentCertificate(t, st, "cert-b", []string{"existing-b"}, nil)
	seedEnrollmentCertificate(t, st, "cert-c", []string{"existing-c"}, nil)

	token, agentID, err := srv.CreateAgentTokenWithCertificates("agent", []string{"cert-a", "cert-b"})
	if err != nil {
		t.Fatal(err)
	}
	_, csrPEM := controlTestCSR(t, "agent")
	rw := doRegister(srv, registerBody(t, token, "", "my-agent", 9123, csrPEM))
	if rw.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rw.Code, rw.Body.String())
	}
	if resp := decodeRegisterResponse(t, rw); resp.AgentID != agentID {
		t.Fatalf("agent id = %q, want %q", resp.AgentID, agentID)
	}

	state := st.State()
	if got, want := state.Certificates["cert-a"].TargetAgents, []string{"existing-a", agentID}; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("cert-a targets = %#v, want %#v", got, want)
	}
	if got, want := state.Certificates["cert-b"].TargetAgents, []string{"existing-b", agentID}; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("cert-b targets = %#v, want %#v", got, want)
	}
	if got := state.Certificates["cert-c"].TargetAgents; len(got) != 1 || got[0] != "existing-c" {
		t.Fatalf("unselected cert-c targets changed: %#v", got)
	}
	certA := state.Certificates["cert-a"]
	if certA.Deploys == nil || certA.Deploys["existing-a"] == nil {
		t.Fatal("existing deploy record was dropped")
	}
	if certA.Deploys["existing-a"].Status != domain.StatusSuccess {
		t.Fatalf("existing deploy status = %q", certA.Deploys["existing-a"].Status)
	}
	if _, ok := certA.Deploys[agentID]; ok {
		t.Fatal("registration created a deploy record")
	}
	if certA.Current != nil {
		t.Fatal("registration unexpectedly changed the certificate version")
	}
}

func TestRegisterWithoutSelectionDoesNotBindCertificates(t *testing.T) {
	srv, st, _ := newControlTestServer(t)
	seedEnrollmentCertificate(t, st, "cert-a", []string{"existing-a"}, nil)

	token, _, err := srv.CreateAgentToken("agent")
	if err != nil {
		t.Fatal(err)
	}
	_, csrPEM := controlTestCSR(t, "agent")
	rw := doRegister(srv, registerBody(t, token, "", "my-agent", 9123, csrPEM))
	if rw.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rw.Code, rw.Body.String())
	}
	if got := st.State().Certificates["cert-a"].TargetAgents; len(got) != 1 || got[0] != "existing-a" {
		t.Fatalf("cert-a targets = %#v, want unchanged", got)
	}
}

func TestRegisterIgnoresCertificateDeletedAfterMint(t *testing.T) {
	srv, st, _ := newControlTestServer(t)
	seedEnrollmentCertificate(t, st, "cert-a", nil, nil)
	seedEnrollmentCertificate(t, st, "cert-b", nil, nil)

	token, agentID, err := srv.CreateAgentTokenWithCertificates("agent", []string{"cert-a", "cert-b"})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.WithState(true, func(state *domain.State) error {
		delete(state.Certificates, "cert-b")
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	_, csrPEM := controlTestCSR(t, "agent")
	rw := doRegister(srv, registerBody(t, token, "", "my-agent", 9123, csrPEM))
	if rw.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rw.Code, rw.Body.String())
	}
	state := st.State()
	if got := state.Certificates["cert-a"].TargetAgents; len(got) != 1 || got[0] != agentID {
		t.Fatalf("cert-a targets = %#v, want [%s]", got, agentID)
	}
	if state.Certificates["cert-b"] != nil {
		t.Fatal("deleted certificate was recreated")
	}
	if rec := state.Tokens[token]; rec == nil || rec.UsedAt.IsZero() {
		t.Fatal("token was not consumed")
	}
}

func TestRegisterReplayDoesNotDuplicateCertificateBinding(t *testing.T) {
	srv, st, _ := newControlTestServer(t)
	seedEnrollmentCertificate(t, st, "cert-a", nil, nil)

	token, agentID, err := srv.CreateAgentTokenWithCertificates("agent", []string{"cert-a"})
	if err != nil {
		t.Fatal(err)
	}
	_, csrPEM := controlTestCSR(t, "agent")
	body := registerBody(t, token, "", "my-agent", 9123, csrPEM)
	if rw := doRegister(srv, body); rw.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rw.Code, rw.Body.String())
	}
	if rw := doRegister(srv, body); rw.Code != http.StatusForbidden {
		t.Fatalf("replay status = %d", rw.Code)
	}
	targets := st.State().Certificates["cert-a"].TargetAgents
	if len(targets) != 1 || targets[0] != agentID {
		t.Fatalf("targets = %#v, want exactly one binding", targets)
	}
}

func TestRegisterIdempotentWhenCertificateAlreadyTargetsAgent(t *testing.T) {
	srv, st, _ := newControlTestServer(t)
	seedEnrollmentCertificate(t, st, "cert-a", []string{"bound-agent"}, nil)
	if err := st.WithState(true, func(state *domain.State) error {
		state.Tokens["bound"] = &domain.TokenRecord{
			Token: "bound", AgentID: "bound-agent", AgentName: "agent",
			CertificateIDs: []string{"cert-a"},
			ExpiresAt:      time.Now().Add(time.Minute),
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	_, csrPEM := controlTestCSR(t, "agent")
	rw := doRegister(srv, registerBody(t, "bound", "", "my-agent", 9123, csrPEM))
	if rw.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rw.Code, rw.Body.String())
	}
	if got := st.State().Certificates["cert-a"].TargetAgents; len(got) != 1 || got[0] != "bound-agent" {
		t.Fatalf("targets = %#v, want no duplicate binding", got)
	}
}

func TestRegisterExpiredTokenWithSelectionBindsNothing(t *testing.T) {
	srv, st, _ := newControlTestServer(t)
	seedEnrollmentCertificate(t, st, "cert-a", nil, nil)

	token, _, err := srv.CreateAgentTokenWithCertificates("agent", []string{"cert-a"})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.WithState(true, func(state *domain.State) error {
		state.Tokens[token].ExpiresAt = time.Now().Add(-time.Minute)
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	_, csrPEM := controlTestCSR(t, "agent")
	rw := doRegister(srv, registerBody(t, token, "", "my-agent", 9123, csrPEM))
	if rw.Code != http.StatusForbidden {
		t.Fatalf("status = %d body=%s", rw.Code, rw.Body.String())
	}
	state := st.State()
	if got := state.Certificates["cert-a"].TargetAgents; len(got) != 0 {
		t.Fatalf("expired token bound targets: %#v", got)
	}
	if len(state.Agents) != 0 {
		t.Fatalf("agents = %d, want 0", len(state.Agents))
	}
}

func TestCreateAgentTokenWithCertificatesPersistenceFailureLeavesNoToken(t *testing.T) {
	srv, st, _ := newControlTestServer(t)
	seedEnrollmentCertificate(t, st, "cert-a", nil, nil)

	if err := os.Mkdir(st.StatePath()+".tmp", 0o700); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(st.StatePath() + ".tmp")

	before := st.State()
	if _, _, err := srv.CreateAgentTokenWithCertificates("agent", []string{"cert-a"}); err == nil {
		t.Fatal("expected persistence failure")
	}
	after := st.State()
	if len(after.Tokens) != len(before.Tokens) {
		t.Fatalf("tokens = %d, want %d", len(after.Tokens), len(before.Tokens))
	}
	if got := after.Certificates["cert-a"].TargetAgents; len(got) != 0 {
		t.Fatalf("failed mint bound targets: %#v", got)
	}
}

func TestRegisterPersistenceFailureWithSelectionLeavesNoBinding(t *testing.T) {
	srv, st, _ := newControlTestServer(t)
	seedEnrollmentCertificate(t, st, "cert-a", []string{"existing-a"}, nil)
	token, _, err := srv.CreateAgentTokenWithCertificates("agent", []string{"cert-a"})
	if err != nil {
		t.Fatal(err)
	}
	_, csrPEM := controlTestCSR(t, "agent")
	body := registerBody(t, token, "", "my-agent", 9123, csrPEM)

	if err := os.Mkdir(st.StatePath()+".tmp", 0o700); err != nil {
		t.Fatal(err)
	}
	rw := doRegister(srv, body)
	if rw.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d body=%s", rw.Code, rw.Body.String())
	}
	state := st.State()
	if rec := state.Tokens[token]; rec == nil || !rec.UsedAt.IsZero() {
		t.Fatal("failed registration consumed the token")
	}
	if got := state.Certificates["cert-a"].TargetAgents; len(got) != 1 || got[0] != "existing-a" {
		t.Fatalf("failed registration changed targets: %#v", got)
	}
	if len(state.Agents) != 0 {
		t.Fatalf("agents = %d, want 0", len(state.Agents))
	}

	if err := os.Remove(st.StatePath() + ".tmp"); err != nil {
		t.Fatal(err)
	}
	retry := doRegister(srv, body)
	if retry.Code != http.StatusOK {
		t.Fatalf("retry status = %d body=%s", retry.Code, retry.Body.String())
	}
	agentID := decodeRegisterResponse(t, retry).AgentID
	if got := st.State().Certificates["cert-a"].TargetAgents; len(got) != 2 || got[0] != "existing-a" || got[1] != agentID {
		t.Fatalf("retry targets = %#v", got)
	}
}

func TestRegisterConcurrentWithSelectionBindsOnce(t *testing.T) {
	srv, st, _ := newControlTestServer(t)
	seedEnrollmentCertificate(t, st, "cert-a", nil, nil)
	token, _, err := srv.CreateAgentTokenWithCertificates("agent", []string{"cert-a"})
	if err != nil {
		t.Fatal(err)
	}
	_, csrPEM := controlTestCSR(t, "agent")
	body := registerBody(t, token, "", "agent", 9123, csrPEM)

	const workers = 8
	var ready sync.WaitGroup
	ready.Add(workers)
	release := make(chan struct{})
	registerBeforeConsume = func() {
		ready.Done()
		<-release
	}
	defer func() { registerBeforeConsume = nil }()
	go func() {
		done := make(chan struct{})
		go func() {
			ready.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
		close(release)
	}()

	codes := make(chan int, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes <- doRegister(srv, body).Code
		}()
	}
	wg.Wait()
	close(codes)

	ok, forbidden := 0, 0
	for code := range codes {
		switch code {
		case http.StatusOK:
			ok++
		case http.StatusForbidden:
			forbidden++
		default:
			t.Fatalf("unexpected status %d", code)
		}
	}
	if ok != 1 || forbidden != workers-1 {
		t.Fatalf("ok=%d forbidden=%d", ok, forbidden)
	}
	state := st.State()
	if len(state.Agents) != 1 {
		t.Fatalf("agents = %d, want 1", len(state.Agents))
	}
	targets := state.Certificates["cert-a"].TargetAgents
	if len(targets) != 1 {
		t.Fatalf("targets = %#v, want exactly one binding", targets)
	}
	for agentID := range state.Agents {
		if targets[0] != agentID {
			t.Fatalf("bound target = %q, want %q", targets[0], agentID)
		}
	}
}
