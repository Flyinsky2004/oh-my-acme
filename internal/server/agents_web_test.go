package server

import (
	"context"
	"crypto/x509"
	"errors"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Flyinsky2004/oh-my-acme/internal/domain"
	"github.com/Flyinsky2004/oh-my-acme/internal/store"
	"github.com/Flyinsky2004/oh-my-acme/internal/updater"
)

// newAgentsTestWeb builds a Web backed by a Server whose lifecycle context and
// mTLS client are usable by the Agent health checks and update tasks.
func newAgentsTestWeb(t *testing.T, st *store.Store, pool *x509.CertPool) *Web {
	t.Helper()
	srv := newAgentUpdatesTestServer(t, st, pool)
	web, err := NewWeb(srv)
	if err != nil {
		t.Fatal(err)
	}
	return web
}

func TestAgentsPageUsesOneCatalogAndShowsLatestVersions(t *testing.T) {
	st := newAgentUpdatesStore(t)
	pool := x509.NewCertPool()
	amd64 := newAgentUpdatesFake(t, pool, "agent-amd64", "1.0.0", "linux", "amd64")
	arm64 := newAgentUpdatesFake(t, pool, "agent-arm64", "1.0.0", "linux", "arm64")
	addAgentUpdatesAgent(t, st, agentUpdatesRegisteredAgent(t, amd64, "1.0.0"))
	addAgentUpdatesAgent(t, st, agentUpdatesRegisteredAgent(t, arm64, "1.0.0"))
	fetches := agentUpdatesInstallCatalog(t, []map[string]any{
		agentUpdatesRelease(1, "v1.5.0", agentUpdatesAMD64Asset, agentUpdatesARM64Asset, agentUpdatesChecksums),
		agentUpdatesRelease(10, "v2.0.0", agentUpdatesAMD64Asset, agentUpdatesARM64Asset, agentUpdatesChecksums),
	})
	web := newAgentsTestWeb(t, st, pool)

	rw := httptest.NewRecorder()
	web.handleAgents(rw, httptest.NewRequest(http.MethodGet, "/agents", nil))
	if rw.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rw.Code, rw.Body.String())
	}
	if got := atomic.LoadInt32(fetches); got != 1 {
		t.Fatalf("catalog fetches = %d, want 1", got)
	}
	body := rw.Body.String()
	for _, want := range []string{
		"agent-amd64", "agent-arm64", "v2.0.0", "v1.5.0",
		`action="/agents/agent-amd64/update"`, `action="/agents/update-all"`, "更新全部",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body does not contain %q", want)
		}
	}
}

func TestAgentsPageShowsCatalogErrorAndKeepsAgentList(t *testing.T) {
	st := newAgentUpdatesStore(t)
	pool := x509.NewCertPool()
	fake := newAgentUpdatesFake(t, pool, "agent-one", "1.0.0", "linux", "amd64")
	addAgentUpdatesAgent(t, st, agentUpdatesRegisteredAgent(t, fake, "1.0.0"))
	previous := fetchAgentCatalog
	fetchAgentCatalog = func(context.Context) (*updater.Catalog, error) {
		return nil, errors.New("github unavailable")
	}
	t.Cleanup(func() { fetchAgentCatalog = previous })
	web := newAgentsTestWeb(t, st, pool)

	rw := httptest.NewRecorder()
	web.handleAgents(rw, httptest.NewRequest(http.MethodGet, "/agents", nil))
	if rw.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rw.Code, rw.Body.String())
	}
	body := rw.Body.String()
	if !strings.Contains(body, "github unavailable") {
		t.Error("catalog error is not visible")
	}
	if !strings.Contains(body, "agent-one") {
		t.Error("agent list disappeared on catalog error")
	}
	if strings.Contains(body, `action="/agents/update-all"`) {
		t.Error("update-all button is offered without version data")
	}
}

func TestAgentRowsMissingVersionResultDoesNotClaimLatest(t *testing.T) {
	st := newAgentUpdatesStore(t)
	web := newAgentsTestWeb(t, st, x509.NewCertPool())
	if err := st.WithState(true, func(state *domain.State) error {
		state.Agents["late-agent"] = &domain.Agent{
			ID: "late-agent", Name: "late-agent", Status: domain.AgentRegistered,
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// Simulate an Agent registered while the shared check was running: it is in
	// the store snapshot but has no entry in the returned options map.
	rows := web.agentRows(map[string]AgentVersionOptions{}, true)
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	if rows[0].VersionHint == "" {
		t.Fatal("a missing version result was rendered as already up to date")
	}
	if strings.Contains(rows[0].VersionHint, "已是最新") {
		t.Fatalf("missing version result hint = %q", rows[0].VersionHint)
	}
	if !strings.Contains(rows[0].VersionHint, "尚未检查") {
		t.Fatalf("missing version result hint = %q", rows[0].VersionHint)
	}

	data := web.agentsPageData(map[string]AgentVersionOptions{}, true)
	data["CSRF"] = "test-csrf"
	var out strings.Builder
	if err := web.tmpl.ExecuteTemplate(&out, "agents", data); err != nil {
		t.Fatal(err)
	}
	body := out.String()
	if !strings.Contains(body, "尚未检查版本，请刷新后重试") {
		t.Error("page does not show the missing-check hint")
	}
	// Scope the "not already up to date" assertion to this Agent's row: the
	// page-level batch hint legitimately mentions agents that are up to date.
	rowStart := strings.Index(body, "late-agent")
	if rowStart < 0 {
		t.Fatal("late-agent row not found")
	}
	rowEnd := strings.Index(body[rowStart:], "</tr>")
	if rowEnd < 0 {
		t.Fatal("late-agent row end not found")
	}
	if row := body[rowStart : rowStart+rowEnd]; strings.Contains(row, "已是最新") {
		t.Errorf("unchecked Agent row claims it is already up to date: %s", row)
	}
}

func TestAgentUpdateAllReportsStartedAndSkipped(t *testing.T) {
	st := newAgentUpdatesStore(t)
	pool := x509.NewCertPool()
	first := newAgentUpdatesFake(t, pool, "agent-a", "1.0.0", "linux", "amd64")
	second := newAgentUpdatesFake(t, pool, "agent-b", "1.0.0", "linux", "amd64")
	latest := newAgentUpdatesFake(t, pool, "agent-latest", "2.0.0", "linux", "amd64")
	addAgentUpdatesAgent(t, st, agentUpdatesRegisteredAgent(t, first, "1.0.0"))
	addAgentUpdatesAgent(t, st, agentUpdatesRegisteredAgent(t, second, "1.0.0"))
	addAgentUpdatesAgent(t, st, agentUpdatesRegisteredAgent(t, latest, "2.0.0"))
	agentUpdatesInstallCatalog(t, []map[string]any{
		agentUpdatesRelease(1, "v2.0.0", agentUpdatesAMD64Asset, agentUpdatesChecksums),
	})
	web := newAgentsTestWeb(t, st, pool)

	rw := httptest.NewRecorder()
	web.handleAgentUpdateAll(rw, httptest.NewRequest(http.MethodPost, "/agents/update-all", nil))
	if rw.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rw.Code, rw.Body.String())
	}
	if body := rw.Body.String(); !strings.Contains(body, "已启动 2 台，跳过 1 台") {
		t.Fatalf("batch feedback missing: %s", body)
	}
	waitForAgentUpdate(t, first, "v2.0.0")
	waitForAgentUpdate(t, second, "v2.0.0")
	if updates := latest.updateVersions(); len(updates) != 0 {
		t.Fatalf("latest agent received %v", updates)
	}
}

func TestAgentUpdateAllAllLatestDoesNotClaimSuccess(t *testing.T) {
	st := newAgentUpdatesStore(t)
	pool := x509.NewCertPool()
	latest := newAgentUpdatesFake(t, pool, "agent-latest", "2.0.0", "linux", "amd64")
	addAgentUpdatesAgent(t, st, agentUpdatesRegisteredAgent(t, latest, "2.0.0"))
	agentUpdatesInstallCatalog(t, []map[string]any{
		agentUpdatesRelease(1, "v2.0.0", agentUpdatesAMD64Asset, agentUpdatesChecksums),
	})
	web := newAgentsTestWeb(t, st, pool)

	rw := httptest.NewRecorder()
	web.handleAgentUpdateAll(rw, httptest.NewRequest(http.MethodPost, "/agents/update-all", nil))
	body := rw.Body.String()
	if !strings.Contains(body, "已启动 0 台，跳过 1 台") {
		t.Fatalf("batch feedback missing: %s", body)
	}
	if !strings.Contains(body, "没有可更新的 Agent") {
		t.Error("no-op batch update did not explain the skip")
	}
	if updates := latest.updateVersions(); len(updates) != 0 {
		t.Fatalf("latest agent received %v", updates)
	}
}

func TestAgentUpdateAllRouteRequiresAuthAndCSRF(t *testing.T) {
	st := newAgentUpdatesStore(t)
	pool := x509.NewCertPool()
	fake := newAgentUpdatesFake(t, pool, "agent-a", "1.0.0", "linux", "amd64")
	addAgentUpdatesAgent(t, st, agentUpdatesRegisteredAgent(t, fake, "1.0.0"))
	agentUpdatesInstallCatalog(t, []map[string]any{
		agentUpdatesRelease(1, "v2.0.0", agentUpdatesAMD64Asset, agentUpdatesChecksums),
	})
	web := newAgentsTestWeb(t, st, pool)
	if err := web.srv.setAdminPassword("admin", "test-password"); err != nil {
		t.Fatal(err)
	}

	// No session: the auth middleware redirects before the handler runs.
	rw := postWeb(web, "/agents/update-all", "", "", nil, false, nil)
	if rw.Code != http.StatusFound {
		t.Fatalf("unauthenticated status = %d, want 302", rw.Code)
	}
	if got := st.State().Agents["agent-a"].UpdateStatus; got == domain.StatusRunning {
		t.Fatal("unauthenticated request started an update")
	}
	if updates := fake.updateVersions(); len(updates) != 0 {
		t.Fatalf("unauthenticated request sent %v", updates)
	}

	id, csrf := loginSession(t, web, "")
	// Missing/wrong CSRF: rejected before any side effect.
	rw = postWeb(web, "/agents/update-all", id, "bad", nil, false, nil)
	if rw.Code != http.StatusForbidden {
		t.Fatalf("bad CSRF status = %d, want 403", rw.Code)
	}
	if got := st.State().Agents["agent-a"].UpdateStatus; got == domain.StatusRunning {
		t.Fatal("CSRF-less request started an update")
	}
	if updates := fake.updateVersions(); len(updates) != 0 {
		t.Fatalf("CSRF-less request sent %v", updates)
	}

	// A valid session and CSRF token reach the handler.
	rw = postWeb(web, "/agents/update-all", id, csrf, nil, false, nil)
	if rw.Code != http.StatusOK {
		t.Fatalf("valid status = %d, body=%s", rw.Code, rw.Body.String())
	}
	if body := rw.Body.String(); !strings.Contains(body, "已启动 1 台，跳过 0 台") {
		t.Fatalf("batch feedback missing: %s", body)
	}
	waitForAgentUpdate(t, fake, "v2.0.0")
}

func TestAgentSingleUpdateRouteStillWorks(t *testing.T) {
	st := newAgentUpdatesStore(t)
	pool := x509.NewCertPool()
	fake := newAgentUpdatesFake(t, pool, "agent-a", "1.0.0", "linux", "amd64")
	addAgentUpdatesAgent(t, st, agentUpdatesRegisteredAgent(t, fake, "1.0.0"))
	agentUpdatesInstallCatalog(t, []map[string]any{
		agentUpdatesRelease(1, "v2.0.0", agentUpdatesAMD64Asset, agentUpdatesChecksums),
	})
	web := newAgentsTestWeb(t, st, pool)
	if err := web.srv.setAdminPassword("admin", "test-password"); err != nil {
		t.Fatal(err)
	}
	id, csrf := loginSession(t, web, "")
	rw := postWeb(web, "/agents/agent-a/update", id, csrf, url.Values{"version": {"v2.0.0"}}, false, nil)
	if rw.Code != http.StatusFound {
		t.Fatalf("status = %d, body=%s", rw.Code, rw.Body.String())
	}
	waitForAgentUpdate(t, fake, "v2.0.0")
}

func TestAgentTokenBindsCertificatesAndKeepsPage(t *testing.T) {
	st := newAgentUpdatesStore(t)
	web := newAgentsTestWeb(t, st, x509.NewCertPool())
	if err := st.WithState(true, func(state *domain.State) error {
		state.Certificates["cert-b"] = &domain.Certificate{ID: "cert-b", RootDomain: "b.example.com"}
		state.Certificates["cert-a"] = &domain.Certificate{ID: "cert-a", RootDomain: "a.example.com"}
		state.Agents["agent-existing"] = &domain.Agent{ID: "agent-existing", Name: "existing-agent", Status: domain.AgentRegistered}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	form := url.Values{"name": {"edge-1"}, "certificates": {"cert-a", "cert-b"}}
	req := httptest.NewRequest(http.MethodPost, "/agents/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rw := httptest.NewRecorder()
	web.handleAgentToken(rw, req)
	if rw.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rw.Code, rw.Body.String())
	}
	body := rw.Body.String()
	for _, want := range []string{
		`value="edge-1"`, `value="cert-a"`, `value="cert-b"`,
		"a.example.com", "b.example.com", "existing-agent",
		"data-command-sudo", "data-command-plain",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body does not contain %q", want)
		}
	}
	if !regexp.MustCompile(`value="cert-a"[^>]*checked`).MatchString(body) ||
		!regexp.MustCompile(`value="cert-b"[^>]*checked`).MatchString(body) {
		t.Error("submitted certificate selection was not preserved")
	}
	state := st.State()
	if len(state.Tokens) != 1 {
		t.Fatalf("tokens = %d, want 1", len(state.Tokens))
	}
	for _, record := range state.Tokens {
		if !reflect.DeepEqual(record.CertificateIDs, []string{"cert-a", "cert-b"}) {
			t.Fatalf("token certificates = %v", record.CertificateIDs)
		}
	}
}

func TestAgentTokenRejectsUnknownCertificateAndKeepsInput(t *testing.T) {
	st := newAgentUpdatesStore(t)
	web := newAgentsTestWeb(t, st, x509.NewCertPool())
	if err := st.WithState(true, func(state *domain.State) error {
		state.Certificates["cert-a"] = &domain.Certificate{ID: "cert-a", RootDomain: "a.example.com"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	form := url.Values{"name": {"edge-1"}, "certificates": {"missing"}}
	req := httptest.NewRequest(http.MethodPost, "/agents/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rw := httptest.NewRecorder()
	web.handleAgentToken(rw, req)
	body := rw.Body.String()
	if !strings.Contains(body, "selected certificate not found") {
		t.Fatalf("error missing: %s", body)
	}
	if !strings.Contains(body, `value="edge-1"`) {
		t.Error("submitted name was not preserved")
	}
	if !strings.Contains(body, "a.example.com") {
		t.Error("certificate options disappeared after an error")
	}
	if len(st.State().Tokens) != 0 {
		t.Fatal("failed token creation stored a token")
	}
}

func TestAgentInstallCommandsDifferOnlyBySudo(t *testing.T) {
	st := newAgentUpdatesStore(t)
	web := newAgentsTestWeb(t, st, x509.NewCertPool())
	name := `sudo <b>"x"&'`
	form := url.Values{"name": {name}}
	req := httptest.NewRequest(http.MethodPost, "/agents/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rw := httptest.NewRecorder()
	web.handleAgentToken(rw, req)
	body := rw.Body.String()
	if strings.Contains(body, "<b>") {
		t.Fatal("user-supplied HTML was not escaped")
	}
	sudoCmd := html.UnescapeString(attributeValue(t, body, "data-command-sudo"))
	plainCmd := html.UnescapeString(attributeValue(t, body, "data-command-plain"))
	if !strings.HasPrefix(sudoCmd, "sudo bash -c ") {
		t.Fatalf("sudo command = %q", sudoCmd)
	}
	if strings.HasPrefix(plainCmd, "sudo ") {
		t.Fatalf("plain command still starts with sudo: %q", plainCmd)
	}
	if strings.TrimPrefix(sudoCmd, "sudo ") != plainCmd {
		t.Fatal("commands differ by more than the outermost sudo")
	}
	if !strings.Contains(plainCmd, "sudo <b>") {
		t.Fatal("the name's own sudo text was rewritten")
	}
	var token string
	for key := range st.State().Tokens {
		token = key
	}
	if token == "" || !strings.Contains(sudoCmd, token) || !strings.Contains(plainCmd, token) {
		t.Fatalf("token missing from commands: %q / %q", sudoCmd, plainCmd)
	}
}

func TestAgentsPageSortsAgentsAndCertificates(t *testing.T) {
	st := newAgentUpdatesStore(t)
	agentUpdatesInstallCatalog(t, []map[string]any{})
	web := newAgentsTestWeb(t, st, x509.NewCertPool())
	if err := st.WithState(true, func(state *domain.State) error {
		for _, name := range []string{"zeta", "alpha", "beta"} {
			state.Agents[name] = &domain.Agent{ID: name, Name: name, Status: domain.AgentDisabled}
		}
		state.Certificates["cert-z"] = &domain.Certificate{ID: "cert-z", RootDomain: "z.example.com"}
		state.Certificates["cert-a"] = &domain.Certificate{ID: "cert-a", RootDomain: "a.example.com"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	rw := httptest.NewRecorder()
	web.handleAgents(rw, httptest.NewRequest(http.MethodGet, "/agents", nil))
	body := rw.Body.String()
	if !(strings.Index(body, "alpha") < strings.Index(body, "beta") &&
		strings.Index(body, "beta") < strings.Index(body, "zeta")) {
		t.Error("agents are not sorted by name")
	}
	if !(strings.Index(body, "a.example.com") < strings.Index(body, "z.example.com")) {
		t.Error("certificates are not sorted by root domain")
	}
}

func attributeValue(t *testing.T, body, name string) string {
	t.Helper()
	match := regexp.MustCompile(regexp.QuoteMeta(name) + `="([^"]*)"`).FindStringSubmatch(body)
	if len(match) != 2 {
		t.Fatalf("attribute %s not found", name)
	}
	return match[1]
}
