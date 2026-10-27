package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Flyinsky2004/oh-my-acme/internal/domain"
)

func TestHandleDeployOnlyTouchesSelectedAgents(t *testing.T) {
	for _, selection := range [][]string{{"agent1"}, {"agent1", "agent1"}, {"agent1", "agent2"}} {
		t.Run(strings.Join(selection, ","), func(t *testing.T) {
			web, st, ca := newDeployFeedbackTestWeb(t)
			address, port := startDeployFeedbackAgent(t, ca)
			certPEM, keyPEM := newDeployFeedbackCertificateMaterial(t)
			version, err := st.WriteCertVersion("cert1", domain.CertificateVersion{
				ID: "v2", IssuedAt: time.Now().Add(-time.Hour), ExpiresAt: time.Now().Add(24 * time.Hour),
			}, certPEM, certPEM, certPEM, keyPEM)
			if err != nil {
				t.Fatal(err)
			}
			targets := []string{"agent1", "agent2", "agent3"}
			setDeployFeedbackCertificate(t, st, &version, targets)
			previous := &domain.AgentDeployState{
				AgentID: "agent3", VersionID: "v1", Status: domain.StatusFailed,
				Error: "previous failure", LastLog: "previous log", LastAttemptAt: time.Now().Add(-time.Hour),
			}
			if err := st.WithState(true, func(state *domain.State) error {
				state.Agents["agent1"] = &domain.Agent{ID: "agent1", Address: address, Port: port}
				state.Agents["agent2"] = &domain.Agent{ID: "agent2", Address: address, Port: port}
				state.Certificates["cert1"].Deploys["agent3"] = previous
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			before := st.State().Certificates["cert1"].Deploys["agent3"]
			form := url.Values{"agents": selection}
			req := httptest.NewRequest(http.MethodPost, "/certificates/cert1/deploy", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.SetPathValue("id", "cert1")
			rw := httptest.NewRecorder()
			web.handleDeploy(rw, req)
			if rw.Code != http.StatusOK {
				t.Fatalf("status=%d, body=%s", rw.Code, rw.Body.String())
			}
			waitCertificateDeploy(t, web.srv, "cert1", domain.StatusSuccess)
			cert := st.State().Certificates["cert1"]
			if !reflect.DeepEqual(cert.TargetAgents, targets) {
				t.Fatalf("configured targets changed: %v", cert.TargetAgents)
			}
			if !reflect.DeepEqual(cert.Deploys["agent3"], before) {
				t.Fatalf("unselected agent state changed: %+v", cert.Deploys["agent3"])
			}
			if len(selection) == 1 || selection[1] == "agent1" {
				if cert.Deploys["agent2"] != nil {
					t.Fatalf("unselected agent2 was deployed: %+v", cert.Deploys["agent2"])
				}
			}
			for _, id := range selection {
				if d := cert.Deploys[id]; d == nil || d.Status != domain.StatusSuccess || d.VersionID != "v2" {
					t.Fatalf("selected agent %s deployment: %+v", id, d)
				}
			}
		})
	}
}

func TestHandleDeployRejectsInvalidSelectionsWithoutStarting(t *testing.T) {
	for _, tt := range []struct {
		name, body, query, message string
		status                     int
	}{
		{name: "empty selection", status: http.StatusUnprocessableEntity, message: errNoSelectedAgents.Error()},
		{name: "query cannot select agents", query: "?agents=agent1", status: http.StatusUnprocessableEntity, message: errNoSelectedAgents.Error()},
		{name: "foreign agent", body: "agents=agent1&agents=outside", status: http.StatusConflict, message: errInvalidTargetAgent.Error()},
		{name: "deleted agent", body: "agents=agent1&agents=deleted", status: http.StatusConflict, message: errTargetAgentRemoved.Error()},
	} {
		t.Run(tt.name, func(t *testing.T) {
			web, st, _ := newDeployFeedbackTestWeb(t)
			setDeployFeedbackCertificate(t, st, &domain.CertificateVersion{ID: "v1"}, []string{"agent1", "deleted"})
			if err := st.WithState(true, func(state *domain.State) error {
				state.Agents["agent1"] = &domain.Agent{ID: "agent1"}
				state.Agents["outside"] = &domain.Agent{ID: "outside"}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			before := st.State().Certificates["cert1"]
			req := httptest.NewRequest(http.MethodPost, "/certificates/cert1/deploy"+tt.query, strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.SetPathValue("id", "cert1")
			rw := httptest.NewRecorder()
			web.handleDeploy(rw, req)
			if rw.Code != tt.status || !strings.Contains(rw.Body.String(), tt.message) {
				t.Fatalf("status=%d, body=%s", rw.Code, rw.Body.String())
			}
			if !reflect.DeepEqual(st.State().Certificates["cert1"], before) {
				t.Fatal("invalid selection changed certificate deployment state")
			}
		})
	}
}

func TestHandleDeployFormUsesOnlyConfiguredTargetsWithoutDeploying(t *testing.T) {
	web, st, _ := newDeployFeedbackTestWeb(t)
	setDeployFeedbackCertificate(t, st, &domain.CertificateVersion{ID: "v1"}, []string{"agent1", "deleted"})
	if err := st.WithState(true, func(state *domain.State) error {
		state.Agents["agent1"] = &domain.Agent{ID: "agent1", Name: "Web <node>", Address: "192.0.2.1"}
		state.Agents["outside"] = &domain.Agent{ID: "outside", Name: "outside-targets"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	before := st.State().Certificates["cert1"]
	req := httptest.NewRequest(http.MethodGet, "/certificates/cert1/deploy", nil)
	req.SetPathValue("id", "cert1")
	rw := httptest.NewRecorder()
	web.handleDeployForm(rw, req)
	if rw.Code != http.StatusOK {
		t.Fatalf("status=%d, body=%s", rw.Code, rw.Body.String())
	}
	body := rw.Body.String()
	for _, want := range []string{`value="agent1" checked`, `value="deleted" disabled`, `hx-confirm="警告：是否要对「example.com」执行「下发证书」操作？"`, `data-agent-name="Web &lt;node&gt;"`, "192.0.2.1", "全选", "取消全选"} {
		if !strings.Contains(body, want) {
			t.Errorf("deploy form missing %q: %s", want, body)
		}
	}
	if strings.Contains(body, "outside-targets") {
		t.Fatal("deploy form includes an agent outside configured targets")
	}
	if !reflect.DeepEqual(st.State().Certificates["cert1"], before) {
		t.Fatal("opening the deploy form changed certificate deployment state")
	}
}

func TestHandleDeployFormRejectsUnavailableCertificate(t *testing.T) {
	for _, tt := range []struct {
		name   string
		cert   *domain.Certificate
		status int
	}{
		{name: "missing", status: http.StatusNotFound},
		{name: "not issued", cert: &domain.Certificate{ID: "cert1"}, status: http.StatusConflict},
		{name: "running", cert: &domain.Certificate{ID: "cert1", Current: &domain.CertificateVersion{ID: "v1"}, TargetAgents: []string{"agent1"}, DeployStatus: domain.StatusRunning}, status: http.StatusConflict},
	} {
		t.Run(tt.name, func(t *testing.T) {
			web, st, _ := newDeployFeedbackTestWeb(t)
			if tt.cert != nil {
				if err := st.WithState(true, func(state *domain.State) error {
					state.Certificates["cert1"] = tt.cert
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			}
			req := httptest.NewRequest(http.MethodGet, "/certificates/cert1/deploy", nil)
			req.SetPathValue("id", "cert1")
			rw := httptest.NewRecorder()
			web.handleDeployForm(rw, req)
			if rw.Code != tt.status {
				t.Fatalf("status=%d, body=%s", rw.Code, rw.Body.String())
			}
		})
	}
}
