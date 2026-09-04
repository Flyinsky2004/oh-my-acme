package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"html/template"
	"io/fs"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Flyinsky2004/oh-my-acme/internal/agent"
	"github.com/Flyinsky2004/oh-my-acme/internal/domain"
	"github.com/Flyinsky2004/oh-my-acme/internal/pki"
	"github.com/Flyinsky2004/oh-my-acme/internal/store"
)

func TestHandleDeployRejectsInvalidCertificateState(t *testing.T) {
	for _, tt := range []struct {
		name       string
		prepare    func(*testing.T, *store.Store)
		statusCode int
		errorText  string
	}{
		{
			name:       "certificate not found",
			prepare:    func(*testing.T, *store.Store) {},
			statusCode: http.StatusNotFound,
			errorText:  "certificate not found",
		},
		{
			name: "certificate not issued",
			prepare: func(t *testing.T, st *store.Store) {
				setDeployFeedbackCertificate(t, st, nil, []string{"agent1"})
			},
			statusCode: http.StatusUnprocessableEntity,
			errorText:  "证书尚未签发，未执行下发",
		},
		{
			name: "certificate is being issued",
			prepare: func(t *testing.T, st *store.Store) {
				setDeployFeedbackCertificate(t, st, &domain.CertificateVersion{ID: "v1"}, []string{"agent1"})
				if err := st.WithState(true, func(state *domain.State) error {
					state.Certificates["cert1"].IssueStatus = domain.StatusRunning
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			},
			statusCode: http.StatusConflict,
			errorText:  "证书正在签发，请稍后再下发",
		},
		{
			name: "no target agents",
			prepare: func(t *testing.T, st *store.Store) {
				setDeployFeedbackCertificate(t, st, &domain.CertificateVersion{ID: "v1"}, nil)
			},
			statusCode: http.StatusUnprocessableEntity,
			errorText:  "未配置目标 Agent，未执行下发",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			web, st, _ := newDeployFeedbackTestWeb(t)
			tt.prepare(t, st)

			req := httptest.NewRequest(http.MethodPost, "/certificates/cert1/deploy", nil)
			req.SetPathValue("id", "cert1")
			rw := httptest.NewRecorder()
			web.handleDeploy(rw, req)

			if rw.Code != tt.statusCode {
				t.Fatalf("status = %d, want %d; body=%s", rw.Code, tt.statusCode, rw.Body.String())
			}
			if contentType := rw.Header().Get("Content-Type"); !strings.HasPrefix(contentType, "application/json") {
				t.Fatalf("Content-Type = %q, want application/json", contentType)
			}
			var response map[string]string
			if err := json.NewDecoder(rw.Body).Decode(&response); err != nil {
				t.Fatalf("decode JSON error response: %v", err)
			}
			if response["error"] != tt.errorText {
				t.Fatalf("error = %q, want %q", response["error"], tt.errorText)
			}
			if trigger := rw.Header().Get("HX-Trigger"); trigger != "" {
				t.Fatalf("HX-Trigger = %q, want empty on failure", trigger)
			}
		})
	}
}

func TestHandleDeployStartsAsyncWhenTargetAgentDoesNotExist(t *testing.T) {
	web, st, _ := newDeployFeedbackTestWeb(t)
	setDeployFeedbackCertificate(t, st, &domain.CertificateVersion{ID: "v1"}, []string{"missing-agent"})

	req := httptest.NewRequest(http.MethodPost, "/certificates/cert1/deploy", nil)
	req.SetPathValue("id", "cert1")
	rw := httptest.NewRecorder()
	web.handleDeploy(rw, req)

	if rw.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rw.Code, http.StatusOK, rw.Body.String())
	}
	if contentType := rw.Header().Get("Content-Type"); !strings.HasPrefix(contentType, "text/html") {
		t.Fatalf("Content-Type = %q, want text/html", contentType)
	}
	if rw.Code == http.StatusBadGateway {
		t.Fatal("deploy must not return 502")
	}
	var trigger map[string]map[string]string
	if err := json.Unmarshal([]byte(rw.Header().Get("HX-Trigger")), &trigger); err != nil {
		t.Fatalf("decode HX-Trigger: %v", err)
	}
	if got := trigger["showToast"]["message"]; got != "已开始异步下发到目标 Agent" {
		t.Fatalf("showToast message = %q", got)
	}
	for _, b := range []byte(rw.Header().Get("HX-Trigger")) {
		if b >= 0x80 {
			t.Fatalf("HX-Trigger contains non-ASCII byte 0x%x", b)
		}
	}
	waitCertificateDeploy(t, web.srv, "cert1", domain.StatusFailed)
	cert := st.State().Certificates["cert1"]
	deploy := cert.Deploys["missing-agent"]
	if deploy == nil || deploy.Status != domain.StatusFailed || deploy.Error != "agent not found" {
		t.Fatalf("missing agent deploy = %+v", deploy)
	}
	logText, err := st.ReadAgentDeployLog("cert1", "missing-agent")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logText, "agent not found") {
		t.Fatalf("deploy log = %q, want agent not found", logText)
	}
}

func TestHandleDeploySetsShowToastTriggerAfterSuccessfulDeployment(t *testing.T) {
	web, st, ca := newDeployFeedbackTestWeb(t)
	address, port := startDeployFeedbackAgent(t, ca)
	certPEM, keyPEM := newDeployFeedbackCertificateMaterial(t)
	version, err := st.WriteCertVersion("cert1", domain.CertificateVersion{
		ID: "v1", IssuedAt: time.Now().Add(-time.Hour), ExpiresAt: time.Now().Add(24 * time.Hour),
	}, certPEM, certPEM, certPEM, keyPEM)
	if err != nil {
		t.Fatalf("write certificate version: %v", err)
	}
	setDeployFeedbackCertificate(t, st, &version, []string{"agent1"})
	if err := st.WithState(true, func(state *domain.State) error {
		state.Agents["agent1"] = &domain.Agent{ID: "agent1", Address: address, Port: port}
		return nil
	}); err != nil {
		t.Fatalf("add deployment agent: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/certificates/cert1/deploy", nil)
	req.SetPathValue("id", "cert1")
	rw := httptest.NewRecorder()
	web.handleDeploy(rw, req)

	if rw.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rw.Code, http.StatusOK, rw.Body.String())
	}
	if contentType := rw.Header().Get("Content-Type"); !strings.HasPrefix(contentType, "text/html") {
		t.Fatalf("Content-Type = %q, want text/html", contentType)
	}
	if !strings.Contains(rw.Body.String(), `id="cert-cert1"`) {
		t.Fatalf("response does not contain refreshed certificate row: %s", rw.Body.String())
	}
	var trigger map[string]map[string]string
	if err := json.Unmarshal([]byte(rw.Header().Get("HX-Trigger")), &trigger); err != nil {
		t.Fatalf("decode HX-Trigger: %v", err)
	}
	if got := trigger["showToast"]["type"]; got != "success" {
		t.Fatalf("showToast type = %q, want success", got)
	}
	if got := trigger["showToast"]["message"]; got != "已开始异步下发到目标 Agent" {
		t.Fatalf("showToast message = %q, want async start message", got)
	}
	waitCertificateDeploy(t, web.srv, "cert1", domain.StatusSuccess)
}

func TestMakeCertificateRowCanDeployRequiresIssuedVersionAndTargetAgent(t *testing.T) {
	version := &domain.CertificateVersion{ID: "v1"}
	for _, tt := range []struct {
		name         string
		current      *domain.CertificateVersion
		targets      []string
		issueStatus  domain.OperationStatus
		deployStatus domain.OperationStatus
		want         bool
	}{
		{name: "no issued version", targets: []string{"agent1"}, want: false},
		{name: "no target agents", current: version, want: false},
		{name: "certificate is being issued", current: version, targets: []string{"agent1"}, issueStatus: domain.StatusRunning, want: false},
		{name: "certificate is being deployed", current: version, targets: []string{"agent1"}, deployStatus: domain.StatusRunning, want: false},
		{name: "issued version and target agent", current: version, targets: []string{"agent1"}, want: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			row := makeCertificateRow(&domain.Certificate{Current: tt.current, TargetAgents: tt.targets, IssueStatus: tt.issueStatus, DeployStatus: tt.deployStatus})
			if row.CanDeploy != tt.want {
				t.Fatalf("CanDeploy = %t, want %t", row.CanDeploy, tt.want)
			}
		})
	}
}

func TestCertificateDeploymentCompleteRequiresEveryCurrentTarget(t *testing.T) {
	version := &domain.CertificateVersion{ID: "v2"}
	for _, tt := range []struct {
		name string
		cert *domain.Certificate
		want bool
	}{
		{name: "missing certificate", want: false},
		{name: "no targets", cert: &domain.Certificate{Current: version}, want: false},
		{
			name: "missing deployment state",
			cert: &domain.Certificate{Current: version, TargetAgents: []string{"agent1"}},
			want: false,
		},
		{
			name: "failed deployment",
			cert: &domain.Certificate{Current: version, TargetAgents: []string{"agent1"}, Deploys: map[string]*domain.AgentDeployState{
				"agent1": {AgentID: "agent1", VersionID: "v2", Status: domain.StatusFailed},
			}},
			want: false,
		},
		{
			name: "previous version",
			cert: &domain.Certificate{Current: version, TargetAgents: []string{"agent1"}, Deploys: map[string]*domain.AgentDeployState{
				"agent1": {AgentID: "agent1", VersionID: "v1", Status: domain.StatusSuccess},
			}},
			want: false,
		},
		{
			name: "all current targets deployed",
			cert: &domain.Certificate{Current: version, TargetAgents: []string{"agent1", "agent2"}, Deploys: map[string]*domain.AgentDeployState{
				"agent1": {AgentID: "agent1", VersionID: "v2", Status: domain.StatusSuccess},
				"agent2": {AgentID: "agent2", VersionID: "v2", Status: domain.StatusSuccess},
			}},
			want: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := certificateDeploymentComplete(tt.cert); got != tt.want {
				t.Fatalf("certificateDeploymentComplete() = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestLayoutProvidesLiveToastContainerAndToastScript(t *testing.T) {
	body, err := fs.ReadFile(templatesFS, "web/templates/layout.html")
	if err != nil {
		t.Fatal(err)
	}
	layout := string(body)
	for _, want := range []string{`aria-live="polite"`, `src="/static/app.js"`} {
		if !strings.Contains(layout, want) {
			t.Errorf("layout does not contain %q", want)
		}
	}
}

func TestToastScriptHandlesSuccessAndErrorEventsWithTextContent(t *testing.T) {
	body, err := fs.ReadFile(staticFS, "web/static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	script := string(body)
	for _, want := range []string{"showToast", "htmx:responseError", "htmx:sendError", "htmx:timeout", "textContent"} {
		if !strings.Contains(script, want) {
			t.Errorf("app.js does not contain %q", want)
		}
	}
	if strings.Contains(script, "innerHTML") {
		t.Error("app.js must not use innerHTML for toast messages")
	}
}

func TestAgentPickerSubmitsEveryAgentInSelectedPanel(t *testing.T) {
	body, err := fs.ReadFile(templatesFS, "web/templates/certificate_new.html")
	if err != nil {
		t.Fatal(err)
	}
	templateSource := string(body)
	for _, want := range []string{"form.addEventListener('submit'", "right.options", "option.selected = true"} {
		if !strings.Contains(templateSource, want) {
			t.Errorf("certificate agent picker does not contain %q", want)
		}
	}
}

func TestCertificateRowDisabledDeployButtonExplainsMissingPrerequisites(t *testing.T) {
	tmpl, err := template.ParseFS(templatesFS, "web/templates/*.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name string
		cert *domain.Certificate
		want string
	}{
		{
			name: "certificate not issued",
			cert: &domain.Certificate{ID: "cert1", TargetAgents: []string{"agent1"}},
			want: "请先签发证书",
		},
		{
			name: "certificate is being issued",
			cert: &domain.Certificate{ID: "cert1", Current: &domain.CertificateVersion{ID: "v1"}, TargetAgents: []string{"agent1"}, IssueStatus: domain.StatusRunning},
			want: "证书正在签发",
		},
		{
			name: "no target agents",
			cert: &domain.Certificate{ID: "cert1", Current: &domain.CertificateVersion{ID: "v1"}},
			want: "未配置目标 Agent",
		},
		{
			name: "certificate is being deployed",
			cert: &domain.Certificate{ID: "cert1", Current: &domain.CertificateVersion{ID: "v1"}, TargetAgents: []string{"agent1"}, DeployStatus: domain.StatusRunning},
			want: "证书正在下发",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var out strings.Builder
			if err := tmpl.ExecuteTemplate(&out, "certificate-row", makeCertificateRow(tt.cert)); err != nil {
				t.Fatalf("render certificate row: %v", err)
			}
			if !strings.Contains(out.String(), `title="`+tt.want+`"`) {
				t.Fatalf("disabled deploy button does not explain why it is unavailable: %s", out.String())
			}
		})
	}
}

func TestStartDeployIsIdempotentWhileRunning(t *testing.T) {
	web, st, _ := newDeployFeedbackTestWeb(t)
	setDeployFeedbackCertificate(t, st, &domain.CertificateVersion{ID: "v1"}, []string{"agent1"})
	if err := st.WithState(true, func(state *domain.State) error {
		state.Certificates["cert1"].DeployStatus = domain.StatusRunning
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	started, err := web.srv.StartDeploy("cert1")
	if err != nil {
		t.Fatal(err)
	}
	if started {
		t.Fatal("duplicate StartDeploy claimed a running certificate")
	}
}

func TestDeployAllContinuesAfterCancelledParentContext(t *testing.T) {
	web, st, ca := newDeployFeedbackTestWeb(t)
	address, port := startDeployFeedbackAgent(t, ca)
	certPEM, keyPEM := newDeployFeedbackCertificateMaterial(t)
	version, err := st.WriteCertVersion("cert1", domain.CertificateVersion{
		ID: "v1", IssuedAt: time.Now().Add(-time.Hour), ExpiresAt: time.Now().Add(24 * time.Hour),
	}, certPEM, certPEM, certPEM, keyPEM)
	if err != nil {
		t.Fatalf("write certificate version: %v", err)
	}
	setDeployFeedbackCertificate(t, st, &version, []string{"missing-agent", "agent1"})
	if err := st.WithState(true, func(state *domain.State) error {
		state.Agents["agent1"] = &domain.Agent{ID: "agent1", Address: address, Port: port}
		return nil
	}); err != nil {
		t.Fatalf("add deployment agent: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := web.srv.DeployAll(ctx, "cert1"); err == nil {
		t.Fatal("expected missing-agent error")
	}
	cert := st.State().Certificates["cert1"]
	missing := cert.Deploys["missing-agent"]
	if missing == nil || missing.Status != domain.StatusFailed || missing.Error != "agent not found" {
		t.Fatalf("missing agent deploy = %+v", missing)
	}
	live := cert.Deploys["agent1"]
	if live == nil || live.Status != domain.StatusSuccess {
		t.Fatalf("live agent deploy = %+v", live)
	}
}

func waitCertificateDeploy(t *testing.T, srv *Server, certID string, want domain.OperationStatus) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		cert := srv.st.State().Certificates[certID]
		if cert != nil && cert.DeployStatus == want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	cert := srv.st.State().Certificates[certID]
	t.Fatalf("timeout waiting for deploy status %s, got %+v", want, cert)
}

func newDeployFeedbackTestWeb(t *testing.T) (*Web, *store.Store, *pki.CA) {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ca, err := pki.NewCA("deploy-feedback-test-ca")
	if err != nil {
		t.Fatal(err)
	}
	clientIdentity, err := ca.SignServerClientIdentity()
	if err != nil {
		t.Fatal(err)
	}
	serverIdentity, err := ca.SignServerIdentity([]net.IP{net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Config{ControlPort: 9444}, slog.Default(), st, ca, clientIdentity, serverIdentity)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	tmpl, err := template.ParseFS(templatesFS, "web/templates/*.html")
	if err != nil {
		t.Fatal(err)
	}
	return &Web{srv: srv, tmpl: tmpl}, st, ca
}

func setDeployFeedbackCertificate(t *testing.T, st *store.Store, version *domain.CertificateVersion, targets []string) {
	t.Helper()
	if err := st.WithState(true, func(state *domain.State) error {
		state.Certificates["cert1"] = &domain.Certificate{
			ID: "cert1", RootDomain: "example.com", Current: version, TargetAgents: targets,
			Deploys: map[string]*domain.AgentDeployState{},
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func startDeployFeedbackAgent(t *testing.T, ca *pki.CA) (string, int) {
	t.Helper()
	identity, err := ca.SignServerIdentity([]net.IP{net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile := filepath.Join(dir, "agent.crt")
	keyFile := filepath.Join(dir, "agent.key")
	serverCAFile := filepath.Join(dir, "server-ca.crt")
	for path, contents := range map[string][]byte{
		certFile: identity.CertPEM, keyFile: identity.KeyPEM, serverCAFile: ca.EncodeCA(),
	} {
		if err := os.WriteFile(path, contents, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	agentServer, err := agent.New(agent.Config{
		CertDir: filepath.Join(dir, "certs"), CertFile: certFile, KeyFile: keyFile, ServerCAFile: serverCAFile,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	tlsConfig, err := agentServer.TLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewUnstartedServer(agentServer.Handler())
	httpServer.TLS = tlsConfig
	httpServer.StartTLS()
	t.Cleanup(httpServer.Close)
	host, portText, err := net.SplitHostPort(strings.TrimPrefix(httpServer.URL, "https://"))
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	return host, port
}

func newDeployFeedbackCertificateMaterial(t *testing.T) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		DNSNames:     []string{"example.com", "*.example.com"},
	}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}
