package server

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Flyinsky2004/oh-my-acme/internal/domain"
	"github.com/Flyinsky2004/oh-my-acme/internal/store"
	"github.com/pquerna/otp/totp"
)

// --- helpers ---

func securityTestWeb(t *testing.T) *Web {
	t.Helper()
	w := loginHistoryWeb(t)
	if err := w.srv.setAdminPassword("admin", "test-password"); err != nil {
		t.Fatal(err)
	}
	return w
}

// loginSession performs a real login through the handler and returns the
// session id and its CSRF token.
func loginSession(t *testing.T, w *Web, otp string) (string, string) {
	t.Helper()
	form := url.Values{"username": {"admin"}, "password": {"test-password"}}
	if otp != "" {
		form.Set("otp", otp)
	}
	r := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rw := httptest.NewRecorder()
	w.Handler().ServeHTTP(rw, r)
	if rw.Code != http.StatusFound {
		t.Fatalf("login status = %d, body=%s", rw.Code, rw.Body.String())
	}
	cookies := rw.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("login cookies = %+v", cookies)
	}
	sess, ok := w.sessions.get(cookies[0].Value)
	if !ok {
		t.Fatal("login did not store a session")
	}
	return sess.id, sess.csrf
}

// postWeb sends a form POST through the full handler. header selects the
// X-CSRF-Token transport instead of the csrf form field.
func postWeb(w *Web, path, id, csrf string, form url.Values, header bool, mutate func(*http.Request)) *httptest.ResponseRecorder {
	if form == nil {
		form = url.Values{}
	}
	if csrf != "" && !header {
		form.Set("csrf", csrf)
	}
	r := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if id != "" {
		r.AddCookie(&http.Cookie{Name: "omc_session", Value: id})
	}
	if csrf != "" && header {
		r.Header.Set("X-CSRF-Token", csrf)
	}
	if mutate != nil {
		mutate(r)
	}
	rw := httptest.NewRecorder()
	w.Handler().ServeHTTP(rw, r)
	return rw
}

type blockingBody struct {
	data    []byte
	started chan struct{}
	release chan struct{}
	once    sync.Once
	offset  int
}

func newBlockingBody(data []byte) *blockingBody {
	return &blockingBody{data: data, started: make(chan struct{}), release: make(chan struct{})}
}

func (b *blockingBody) Read(p []byte) (int, error) {
	b.once.Do(func() { close(b.started) })
	<-b.release
	if b.offset >= len(b.data) {
		return 0, io.EOF
	}
	n := copy(p, b.data[b.offset:])
	b.offset += n
	return n, nil
}

type deadlineRecorder struct {
	*httptest.ResponseRecorder
	deadlines []time.Time
}

func (d *deadlineRecorder) SetReadDeadline(t time.Time) error {
	d.deadlines = append(d.deadlines, t)
	return nil
}

func setTelegramConfig(t *testing.T, w *Web, token string, enabled bool, chatID int64) {
	t.Helper()
	if err := w.srv.st.Update(func(st *domain.State) error {
		st.Config.TelegramToken = token
		st.Config.TelegramEnabled = enabled
		st.Config.TelegramChatID = chatID
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// --- CSRF ---

func TestCSRFFormAndHTMXHeader(t *testing.T) {
	w := securityTestWeb(t)
	id, csrf := loginSession(t, w, "")

	rw := postWeb(w, "/settings", id, csrf, url.Values{"email": {"form@example.com"}}, false, nil)
	if rw.Code != http.StatusFound {
		t.Fatalf("form CSRF status = %d, body=%s", rw.Code, rw.Body.String())
	}
	if got := w.srv.st.State().Config.ACMEAccountEmail; got != "form@example.com" {
		t.Fatalf("form write did not apply: %q", got)
	}

	rw = postWeb(w, "/agents/token", id, csrf, url.Values{"name": {"htmx-agent"}}, true, nil)
	if rw.Code != http.StatusOK {
		t.Fatalf("HTMX header CSRF status = %d, body=%s", rw.Code, rw.Body.String())
	}
	if len(w.srv.st.State().Tokens) != 1 {
		t.Fatalf("HTMX write did not create a token: %+v", w.srv.st.State().Tokens)
	}
}

func TestCSRFRejectsMissingBadCrossSessionAndQuery(t *testing.T) {
	w := securityTestWeb(t)
	id1, csrf1 := loginSession(t, w, "")
	id2, csrf2 := loginSession(t, w, "")
	before := len(w.srv.st.State().Tokens)

	for _, tt := range []struct {
		name, id, csrf, path string
	}{
		{name: "missing", id: id1, path: "/agents/token"},
		{name: "bad", id: id1, csrf: "deadbeef", path: "/agents/token"},
		{name: "cross session", id: id1, csrf: csrf2, path: "/agents/token"},
		{name: "query only", id: id1, path: "/agents/token?csrf=" + csrf1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			rw := postWeb(w, tt.path, tt.id, tt.csrf, url.Values{"name": {"denied"}}, false, nil)
			if rw.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body=%s", rw.Code, rw.Body.String())
			}
			if len(w.srv.st.State().Tokens) != before {
				t.Fatal("rejected request created a token")
			}
		})
	}

	rw := postWeb(w, "/agents/token", id2, csrf2, url.Values{"name": {"allowed"}}, false, nil)
	if rw.Code != http.StatusOK || len(w.srv.st.State().Tokens) != before+1 {
		t.Fatalf("valid session token rejected: %d %s", rw.Code, rw.Body.String())
	}
}

func TestCSRFNoSideEffects(t *testing.T) {
	w := securityTestWeb(t)
	id, _ := loginSession(t, w, "")
	st := w.srv.st

	if err := st.Update(func(state *domain.State) error {
		state.Certificates["cert1"] = &domain.Certificate{
			ID: "cert1", RootDomain: "example.com", Current: &domain.CertificateVersion{ID: "v1"},
			TargetAgents: []string{"agent1"}, Deploys: map[string]*domain.AgentDeployState{},
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	beforeCerts := len(st.State().Certificates)
	beforeTokens := len(st.State().Tokens)
	beforeCreds := len(st.State().Credentials)
	beforeCAs := len(st.State().CAs)
	beforeEmail := st.State().Config.ACMEAccountEmail
	beforeUpdate := w.srv.SelfUpdate().Status

	requests := []struct {
		name, path string
		form       url.Values
	}{
		{name: "settings", path: "/settings", form: url.Values{"email": {"evil@example.com"}}},
		{name: "delete certificate", path: "/certificates/cert1/delete"},
		{name: "issue certificate", path: "/certificates/cert1/issue"},
		{name: "deploy certificate", path: "/certificates/cert1/deploy", form: url.Values{"agents": {"agent1"}}},
		{name: "create agent token", path: "/agents/token", form: url.Values{"name": {"evil"}}},
		{name: "create credential", path: "/credentials", form: url.Values{"name": {"evil"}, "token": {"t"}, "zone_id": {"z"}, "account_id": {"a"}}},
		{name: "add CA", path: "/settings/ca", form: url.Values{"name": {"evil"}, "directory_url": {"https://evil.test/directory"}}},
		{name: "server update", path: "/settings/update", form: url.Values{"version": {"v9.9.9"}}},
	}
	for _, req := range requests {
		t.Run(req.name, func(t *testing.T) {
			rw := postWeb(w, req.path, id, "bad", req.form, false, nil)
			if rw.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body=%s", rw.Code, rw.Body.String())
			}
		})
	}

	state := st.State()
	if len(state.Certificates) != beforeCerts || state.Certificates["cert1"] == nil {
		t.Fatal("rejected request deleted a certificate")
	}
	if state.Certificates["cert1"].DeployStatus == domain.StatusRunning {
		t.Fatal("rejected request started a deployment")
	}
	if state.Certificates["cert1"].IssueStatus == domain.StatusRunning {
		t.Fatal("rejected request started an issuance")
	}
	if len(state.Tokens) != beforeTokens || len(state.Credentials) != beforeCreds || len(state.CAs) != beforeCAs {
		t.Fatal("rejected request mutated collections")
	}
	if state.Config.ACMEAccountEmail != beforeEmail {
		t.Fatal("rejected request changed settings")
	}
	if w.srv.SelfUpdate().Status != beforeUpdate {
		t.Fatal("rejected request started an update")
	}
}

// TestCSRFSlowBodyRevocation proves the token is re-validated against the
// current session after a slow body read, not against a pre-read snapshot.
func TestCSRFSlowBodyRevocation(t *testing.T) {
	for _, tt := range []struct {
		name   string
		revoke func(*Web, string)
	}{
		{name: "delete", revoke: func(w *Web, id string) { w.sessions.delete(id) }},
		{name: "rotate", revoke: func(w *Web, id string) { w.sessions.rotate("admin") }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			w := securityTestWeb(t)
			id, csrf := loginSession(t, w, "")
			form := url.Values{"csrf": {csrf}, "name": {"slow"}}
			body := newBlockingBody([]byte(form.Encode()))
			r := httptest.NewRequest("POST", "/agents/token", body)
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.AddCookie(&http.Cookie{Name: "omc_session", Value: id})
			rw := httptest.NewRecorder()
			done := make(chan struct{})
			go func() {
				w.Handler().ServeHTTP(rw, r)
				close(done)
			}()
			<-body.started
			tt.revoke(w, id)
			close(body.release)
			<-done
			if rw.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body=%s", rw.Code, rw.Body.String())
			}
			if len(w.srv.st.State().Tokens) != 0 {
				t.Fatal("revoked session still created a token")
			}
		})
	}
}

// --- origin ---

func TestOriginExactSameOrigin(t *testing.T) {
	w := securityTestWeb(t)
	id, csrf := loginSession(t, w, "")
	for i, tt := range []struct {
		name, origin, referer, host string
		tls, want                   bool
	}{
		{name: "same origin", origin: "https://example.com", host: "example.com", tls: true, want: true},
		{name: "sibling domain", origin: "https://evil.example.com", host: "example.com", tls: true},
		{name: "foreign domain", origin: "https://evil.test", host: "example.com", tls: true},
		{name: "null origin", origin: "null", host: "example.com", tls: true},
		{name: "scheme mismatch", origin: "http://example.com", host: "example.com", tls: true},
		{name: "origin with path", origin: "https://example.com/path", host: "example.com", tls: true},
		{name: "origin with userinfo", origin: "https://user@example.com", host: "example.com", tls: true},
		{name: "referer same origin", referer: "https://example.com/settings?x=1", host: "example.com", tls: true, want: true},
		{name: "referer sibling", referer: "https://evil.example.com/settings", host: "example.com", tls: true},
		{name: "no origin", host: "example.com", tls: true, want: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			before := len(w.srv.st.State().Tokens)
			rw := postWeb(w, "/agents/token", id, csrf, url.Values{"name": {fmt.Sprintf("origin-%d", i)}}, false, func(r *http.Request) {
				r.Host = tt.host
				if tt.tls {
					r.TLS = &tls.ConnectionState{}
				}
				if tt.origin != "" {
					r.Header.Set("Origin", tt.origin)
				}
				if tt.referer != "" {
					r.Header.Set("Referer", tt.referer)
				}
			})
			if tt.want {
				if rw.Code != http.StatusOK {
					t.Fatalf("allowed origin rejected: %d %s", rw.Code, rw.Body.String())
				}
				return
			}
			if rw.Code != http.StatusForbidden {
				t.Fatalf("origin accepted: %d %s", rw.Code, rw.Body.String())
			}
			if len(w.srv.st.State().Tokens) != before {
				t.Fatal("rejected origin created a token")
			}
		})
	}
}

func TestOriginTrustedProxyAndForgedHeaders(t *testing.T) {
	w := securityTestWeb(t)
	w.srv.cfg.TrustedProxies = []string{"127.0.0.1"}
	id, csrf := loginSession(t, w, "")
	for i, tt := range []struct {
		name, remote, host, xfp, xfh, forwarded string
		tls, want                               bool
	}{
		{name: "trusted proxy", remote: "127.0.0.1:1234", host: "internal:8080", xfp: "https", xfh: "acme.example.com", want: true},
		{name: "forged from untrusted", remote: "192.0.2.1:1234", host: "internal:8080", xfp: "https", xfh: "acme.example.com"},
		{name: "trusted forwarded", remote: "127.0.0.1:1234", host: "internal:8080", forwarded: "proto=https;host=acme.example.com", want: true},
		{name: "direct tls", remote: "192.0.2.1:1234", host: "acme.example.com", tls: true, want: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			before := len(w.srv.st.State().Tokens)
			rw := postWeb(w, "/agents/token", id, csrf, url.Values{"name": {fmt.Sprintf("proxy-%d", i)}}, false, func(r *http.Request) {
				r.RemoteAddr = tt.remote
				r.Host = tt.host
				if tt.tls {
					r.TLS = &tls.ConnectionState{}
				}
				if tt.xfp != "" {
					r.Header.Set("X-Forwarded-Proto", tt.xfp)
				}
				if tt.xfh != "" {
					r.Header.Set("X-Forwarded-Host", tt.xfh)
				}
				if tt.forwarded != "" {
					r.Header.Set("Forwarded", tt.forwarded)
				}
				r.Header.Set("Origin", "https://acme.example.com")
			})
			if tt.want {
				if rw.Code != http.StatusOK {
					t.Fatalf("trusted origin rejected: %d %s", rw.Code, rw.Body.String())
				}
				return
			}
			if rw.Code != http.StatusForbidden {
				t.Fatalf("forged origin accepted: %d %s", rw.Code, rw.Body.String())
			}
			if len(w.srv.st.State().Tokens) != before {
				t.Fatal("forged origin created a token")
			}
		})
	}

	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "127.0.0.1:1234"
	r.Header.Set("Forwarded", "proto=https;host=acme.example.com")
	rw := httptest.NewRecorder()
	w.sessionCookieAndSet(rw, r, "cookie-test")
	if cookies := rw.Result().Cookies(); len(cookies) != 1 || !cookies[0].Secure {
		t.Fatalf("trusted Forwarded proto did not mark the cookie Secure: %+v", cookies)
	}
}

// --- body limits / lock behaviour ---

func TestLoginSlowBodyDoesNotHoldAuthMu(t *testing.T) {
	w := securityTestWeb(t)
	body := newBlockingBody([]byte("username=admin&password=test-password"))
	r := httptest.NewRequest("POST", "/login", body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rw := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		w.Handler().ServeHTTP(rw, r)
		close(done)
	}()
	<-body.started
	if !w.authMu.TryLock() {
		t.Fatal("authMu held while the client body was being read")
	}
	w.authMu.Unlock()
	close(body.release)
	<-done
}

func TestLoginOversizedBody(t *testing.T) {
	w := securityTestWeb(t)
	r := httptest.NewRequest("POST", "/login", strings.NewReader(strings.Repeat("a", maxLoginBody+1)))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rw := httptest.NewRecorder()
	w.Handler().ServeHTTP(rw, r)
	if rw.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413; body=%s", rw.Code, rw.Body.String())
	}
}

func TestAuthReadDeadlineIsSetAndCleared(t *testing.T) {
	w := securityTestWeb(t)
	fixed := time.Unix(1800000000, 0)
	w.now = func() time.Time { return fixed }
	w.authReadTimeout = 2 * time.Second
	rw := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	r := httptest.NewRequest("POST", "/login", strings.NewReader("username=a"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if !w.prepareBody(rw, r, 1024) {
		t.Fatalf("prepareBody failed: %s", rw.Body.String())
	}
	if len(rw.deadlines) < 2 {
		t.Fatalf("deadlines = %v, want set and cleared", rw.deadlines)
	}
	if !rw.deadlines[0].Equal(fixed.Add(2 * time.Second)) {
		t.Fatalf("deadline = %v, want %v", rw.deadlines[0], fixed.Add(2*time.Second))
	}
	if !rw.deadlines[len(rw.deadlines)-1].IsZero() {
		t.Fatal("read deadline was not cleared after parsing")
	}
}

// --- rate limiting ---

func TestBadOriginDoesNotConsumeAccountQuota(t *testing.T) {
	w := securityTestWeb(t)
	secret, _ := enableTestFactor(t, w)
	now := time.Unix(1800000000, 0)
	w.now = func() time.Time { return now }
	w.sourceLimiter = newSourceLimiter(1000, time.Minute, 100)

	for i := 0; i < 20; i++ {
		rw := postWeb(w, "/login", "", "", url.Values{"username": {"admin"}, "password": {"wrong"}}, false, func(r *http.Request) {
			r.Header.Set("Origin", "https://evil.test")
			r.RemoteAddr = "192.0.2.10:1234"
		})
		if rw.Code != http.StatusForbidden {
			t.Fatalf("bad-origin attempt %d status = %d", i, rw.Code)
		}
	}
	code, _ := totp.GenerateCode(secret, now)
	if _, csrf := loginSession(t, w, code); csrf == "" {
		t.Fatal("bad-origin flood exhausted the account quota")
	}
}

func TestWrongPasswordDoesNotConsumeAccountQuota(t *testing.T) {
	w := securityTestWeb(t)
	secret, _ := enableTestFactor(t, w)
	now := time.Unix(1800000000, 0)
	w.now = func() time.Time { return now }
	w.sourceLimiter = newSourceLimiter(1000, time.Minute, 100)

	for i := 0; i < 20; i++ {
		rw := postWeb(w, "/login", "", "", url.Values{"username": {"admin"}, "password": {"wrong"}}, false, nil)
		if rw.Code != http.StatusOK {
			t.Fatalf("wrong-password attempt %d status = %d", i, rw.Code)
		}
	}
	code, _ := totp.GenerateCode(secret, now)
	if _, csrf := loginSession(t, w, code); csrf == "" {
		t.Fatal("wrong-password flood exhausted the account quota")
	}
}

func TestSourceLimiterIsolationAndReset(t *testing.T) {
	w := securityTestWeb(t)
	w.sourceLimiter = newSourceLimiter(2, time.Minute, 100)
	now := time.Unix(1800000000, 0)
	w.now = func() time.Time { return now }
	attempt := func(remote string) int {
		rw := postWeb(w, "/login", "", "", url.Values{"username": {"admin"}, "password": {"wrong"}}, false, func(r *http.Request) {
			r.RemoteAddr = remote
		})
		return rw.Code
	}
	if attempt("192.0.2.1:1") == http.StatusTooManyRequests {
		t.Fatal("first attempt limited")
	}
	if attempt("192.0.2.1:2") == http.StatusTooManyRequests {
		t.Fatal("second attempt limited")
	}
	if attempt("192.0.2.1:3") != http.StatusTooManyRequests {
		t.Fatal("third attempt from the same source was not limited")
	}
	if attempt("192.0.2.2:1") == http.StatusTooManyRequests {
		t.Fatal("a different source was limited by another source's quota")
	}
	now = now.Add(61 * time.Second)
	if attempt("192.0.2.1:4") == http.StatusTooManyRequests {
		t.Fatal("source limiter never resets")
	}
}

func TestAccountQuotaUsesControllableClock(t *testing.T) {
	w := securityTestWeb(t)
	_, _ = enableTestFactor(t, w)
	now := time.Unix(1800000000, 0)
	w.now = func() time.Time { return now }
	w.sourceLimiter = newSourceLimiter(1000, time.Minute, 100)
	attempt := func() int {
		rw := postWeb(w, "/login", "", "", url.Values{
			"username": {"admin"}, "password": {"test-password"}, "otp": {"badotp"},
		}, false, nil)
		return rw.Code
	}
	for i := 0; i < 10; i++ {
		if code := attempt(); code == http.StatusTooManyRequests {
			t.Fatalf("attempt %d limited too early", i)
		}
	}
	if code := attempt(); code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", code)
	}
	now = now.Add(61 * time.Second)
	if code := attempt(); code == http.StatusTooManyRequests {
		t.Fatal("account quota never resets")
	}
}

// --- expensive-work gate ---

func TestPasswordWorkGateRejectsWithoutHoldingAuthMu(t *testing.T) {
	w := securityTestWeb(t)
	w.passwordGate = newWorkGate(1)
	if !w.passwordGate.tryAcquire() {
		t.Fatal("could not occupy the gate")
	}
	rw := postWeb(w, "/login", "", "", url.Values{"username": {"admin"}, "password": {"test-password"}}, false, nil)
	if rw.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429; body=%s", rw.Code, rw.Body.String())
	}
	if !w.authMu.TryLock() {
		t.Fatal("authMu held while the password gate was saturated")
	}
	w.authMu.Unlock()
	w.passwordGate.release()
	rw = postWeb(w, "/login", "", "", url.Values{"username": {"admin"}, "password": {"test-password"}}, false, nil)
	if rw.Code != http.StatusFound {
		t.Fatalf("login after gate release = %d, want 302", rw.Code)
	}
}

func TestPasswordWorkGateCoversSetupAndTwoFactor(t *testing.T) {
	t.Run("setup", func(t *testing.T) {
		w := loginHistoryWeb(t)
		w.passwordGate = newWorkGate(1)
		token, err := w.srv.InitialSetupToken()
		if err != nil {
			t.Fatal(err)
		}
		form := url.Values{"username": {"admin"}, "password": {"test-password"}, "setup_token": {token}}
		if !w.passwordGate.tryAcquire() {
			t.Fatal("could not occupy the gate")
		}
		rw := postWeb(w, "/setup", "", "", form, false, nil)
		if rw.Code != http.StatusTooManyRequests {
			t.Fatalf("status = %d, want 429; body=%s", rw.Code, rw.Body.String())
		}
		if w.srv.getAdmin().SetupTokenUsed {
			t.Fatal("gated setup still initialized the admin")
		}
		w.passwordGate.release()
		rw = postWeb(w, "/setup", "", "", form, false, nil)
		if rw.Code != http.StatusFound {
			t.Fatalf("setup after gate release = %d, body=%s", rw.Code, rw.Body.String())
		}
	})

	t.Run("two factor start", func(t *testing.T) {
		w := securityTestWeb(t)
		w.passwordGate = newWorkGate(1)
		id, csrf := loginSession(t, w, "")
		if !w.passwordGate.tryAcquire() {
			t.Fatal("could not occupy the gate")
		}
		rw := postWeb(w, "/settings/2fa/start", id, csrf, url.Values{"password": {"test-password"}}, false, nil)
		if rw.Code != http.StatusTooManyRequests {
			t.Fatalf("status = %d, want 429; body=%s", rw.Code, rw.Body.String())
		}
		w.passwordGate.release()
		rw = postWeb(w, "/settings/2fa/start", id, csrf, url.Values{"password": {"test-password"}}, false, nil)
		if rw.Code != http.StatusFound {
			t.Fatalf("start after gate release = %d, body=%s", rw.Code, rw.Body.String())
		}
	})

	t.Run("telegram reauthentication", func(t *testing.T) {
		w := securityTestWeb(t)
		w.passwordGate = newWorkGate(1)
		setTelegramConfig(t, w, "123456:abcdefghijklmnopqrstuvwxyz", false, 0)
		id, csrf := loginSession(t, w, "")
		form := url.Values{"tg_token": {"654321:zyxwvutsrqponmlkjihgfedcba"}, "password": {"test-password"}}
		if !w.passwordGate.tryAcquire() {
			t.Fatal("could not occupy the gate")
		}
		rw := postWeb(w, "/settings", id, csrf, form, false, nil)
		if rw.Code != http.StatusTooManyRequests {
			t.Fatalf("status = %d, want 429; body=%s", rw.Code, rw.Body.String())
		}
		if got := w.srv.st.State().Config.TelegramToken; got != "123456:abcdefghijklmnopqrstuvwxyz" {
			t.Fatal("gated reauthentication changed the token")
		}
		w.passwordGate.release()
		rw = postWeb(w, "/settings", id, csrf, form, false, nil)
		if rw.Code != http.StatusFound {
			t.Fatalf("settings after gate release = %d, body=%s", rw.Code, rw.Body.String())
		}
	})
}

// --- login revocation race ---

func TestCommitLoginRejectsStaleGeneration(t *testing.T) {
	w := securityTestWeb(t)
	secret, _ := enableTestFactor(t, w)
	now := time.Unix(1800000000, 0)
	w.now = func() time.Time { return now }
	admin := w.srv.getAdmin()
	generation := w.sessions.currentGeneration()
	// Simulate a 2FA enable/disable rotating sessions while the login was
	// verifying its password.
	w.sessions.rotate("admin")
	code, _ := totp.GenerateCode(secret, now)
	r := httptest.NewRequest("POST", "/login", nil)
	r.PostForm = url.Values{"otp": {code}}
	rw := httptest.NewRecorder()
	id, ok := w.commitLogin(rw, r, "admin", admin, generation, code)
	if ok || id != "" {
		t.Fatal("stale login created a session")
	}
	if w.sessions.count() != 1 {
		t.Fatalf("sessions = %d, want only the rotated session", w.sessions.count())
	}

	// The same one-time code is still unused and a fresh generation succeeds.
	generation = w.sessions.currentGeneration()
	rw = httptest.NewRecorder()
	id, ok = w.commitLogin(rw, r, "admin", admin, generation, code)
	if !ok || id == "" {
		t.Fatalf("fresh login failed: %d %s", rw.Code, rw.Body.String())
	}
	if w.sessions.count() != 2 {
		t.Fatalf("sessions = %d, want 2", w.sessions.count())
	}
}

// --- bootstrap ---

func TestInitialSetupTokenConcurrentAndSingleWinner(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	srv := &Server{st: st}
	const workers = 4
	tokens := make([]string, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			token, err := srv.InitialSetupToken()
			if err != nil {
				t.Errorf("InitialSetupToken: %v", err)
			}
			tokens[i] = token
		}(i)
	}
	wg.Wait()
	for i := 1; i < workers; i++ {
		if tokens[i] == "" || tokens[i] != tokens[0] {
			t.Fatalf("tokens[%d] = %q, want %q", i, tokens[i], tokens[0])
		}
	}

	hash, err := hashPassword("test-password")
	if err != nil {
		t.Fatal(err)
	}
	errs := make([]error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = srv.setupAdminWithHash("admin", hash, tokens[0])
		}(i)
	}
	wg.Wait()
	successes := 0
	for _, err := range errs {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, errSetupTokenInvalid):
		default:
			t.Fatalf("unexpected setup error: %v", err)
		}
	}
	if successes != 1 {
		t.Fatalf("successful initializations = %d, want 1", successes)
	}
	if !st.State().Admin.SetupTokenUsed {
		t.Fatal("admin was not initialized")
	}
}

func TestSetupDiskFailureIsRetryable(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	srv := &Server{st: st}
	token, err := srv.InitialSetupToken()
	if err != nil {
		t.Fatal(err)
	}
	hash, err := hashPassword("test-password")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(st.StatePath()+".tmp", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := srv.setupAdminWithHash("admin", hash, token); err == nil {
		t.Fatal("expected a disk failure")
	}
	if st.State().Admin.SetupTokenUsed {
		t.Fatal("failed write consumed the setup token in memory")
	}
	if err := os.RemoveAll(st.StatePath() + ".tmp"); err != nil {
		t.Fatal(err)
	}
	if err := srv.setupAdminWithHash("admin", hash, token); err != nil {
		t.Fatalf("retry after disk recovery: %v", err)
	}
	if !st.State().Admin.SetupTokenUsed {
		t.Fatal("retry did not initialize the admin")
	}
}

// --- Telegram re-authentication ---

func TestTelegramReauthenticationWithoutTwoFactor(t *testing.T) {
	w := securityTestWeb(t)
	setTelegramConfig(t, w, "123456:abcdefghijklmnopqrstuvwxyz", false, 0)
	id, csrf := loginSession(t, w, "")

	// Wrong password changes nothing.
	rw := postWeb(w, "/settings", id, csrf, url.Values{
		"tg_token": {"654321:zyxwvutsrqponmlkjihgfedcba"}, "password": {"wrong"},
	}, false, nil)
	if rw.Code != http.StatusForbidden {
		t.Fatalf("wrong password status = %d, want 403", rw.Code)
	}
	if got := w.srv.st.State().Config.TelegramToken; got != "123456:abcdefghijklmnopqrstuvwxyz" {
		t.Fatal("wrong password changed the token")
	}

	// Missing password also changes nothing.
	rw = postWeb(w, "/settings", id, csrf, url.Values{
		"tg_token": {"654321:zyxwvutsrqponmlkjihgfedcba"},
	}, false, nil)
	if rw.Code != http.StatusForbidden {
		t.Fatalf("missing password status = %d, want 403", rw.Code)
	}

	// Correct password changes the token.
	rw = postWeb(w, "/settings", id, csrf, url.Values{
		"tg_token": {"654321:zyxwvutsrqponmlkjihgfedcba"}, "password": {"test-password"},
	}, false, nil)
	if rw.Code != http.StatusFound {
		t.Fatalf("valid reauthentication status = %d, body=%s", rw.Code, rw.Body.String())
	}
	if got := w.srv.st.State().Config.TelegramToken; got != "654321:zyxwvutsrqponmlkjihgfedcba" {
		t.Fatalf("token = %q", got)
	}

	// Enabling the bot is also a sensitive control change.
	rw = postWeb(w, "/settings", id, csrf, url.Values{
		"tg_enabled": {"on"}, "password": {"test-password"},
	}, false, nil)
	if rw.Code != http.StatusFound || !w.srv.st.State().Config.TelegramEnabled {
		t.Fatalf("enable status = %d, enabled=%v", rw.Code, w.srv.st.State().Config.TelegramEnabled)
	}
	rw = postWeb(w, "/settings", id, csrf, url.Values{"tg_enabled": {"off"}}, false, nil)
	if rw.Code != http.StatusForbidden || !w.srv.st.State().Config.TelegramEnabled {
		t.Fatalf("disabling without password status = %d, enabled=%v", rw.Code, w.srv.st.State().Config.TelegramEnabled)
	}
}

func TestTelegramReauthenticationWithTwoFactor(t *testing.T) {
	w := securityTestWeb(t)
	secret, codes := enableTestFactor(t, w)
	setTelegramConfig(t, w, "123456:abcdefghijklmnopqrstuvwxyz", false, 0)
	now := time.Unix(1800000000, 0)
	w.now = func() time.Time { return now }
	loginCode, _ := totp.GenerateCode(secret, now)
	id, csrf := loginSession(t, w, loginCode)

	now = now.Add(30 * time.Second)
	code, _ := totp.GenerateCode(secret, now)
	change := func(token, password, otp string) *httptest.ResponseRecorder {
		return postWeb(w, "/settings", id, csrf, url.Values{
			"tg_token": {token}, "password": {password}, "otp": {otp},
		}, false, nil)
	}

	if rw := change("654321:zyxwvutsrqponmlkjihgfedcba", "test-password", code); rw.Code != http.StatusFound {
		t.Fatalf("valid 2FA reauthentication = %d, body=%s", rw.Code, rw.Body.String())
	}
	if got := w.srv.st.State().Config.TelegramToken; got != "654321:zyxwvutsrqponmlkjihgfedcba" {
		t.Fatalf("token = %q", got)
	}
	// The same code is one-time.
	if rw := change("111111:aaaaaaaaaaaaaaaaaaaaaaaa", "test-password", code); rw.Code != http.StatusForbidden {
		t.Fatalf("replayed code status = %d, want 403", rw.Code)
	}
	if got := w.srv.st.State().Config.TelegramToken; got != "654321:zyxwvutsrqponmlkjihgfedcba" {
		t.Fatal("replayed code changed the token")
	}

	// A wrong password must not consume the code.
	now = now.Add(30 * time.Second)
	code, _ = totp.GenerateCode(secret, now)
	if rw := change("111111:aaaaaaaaaaaaaaaaaaaaaaaa", "wrong", code); rw.Code != http.StatusForbidden {
		t.Fatalf("wrong password status = %d, want 403", rw.Code)
	}
	if rw := change("111111:aaaaaaaaaaaaaaaaaaaaaaaa", "test-password", code); rw.Code != http.StatusFound {
		t.Fatalf("code consumed by wrong password: %d, body=%s", rw.Code, rw.Body.String())
	}

	// A recovery code works and is removed.
	if rw := change("222222:bbbbbbbbbbbbbbbbbbbbbbbb", "test-password", codes[0]); rw.Code != http.StatusFound {
		t.Fatalf("recovery code status = %d, body=%s", rw.Code, rw.Body.String())
	}
	if len(w.srv.getAdmin().TwoFactor.RecoveryHashes) != 9 {
		t.Fatalf("recovery codes remaining = %d, want 9", len(w.srv.getAdmin().TwoFactor.RecoveryHashes))
	}

	// Missing OTP is rejected.
	if rw := change("333333:cccccccccccccccccccccccc", "test-password", ""); rw.Code != http.StatusForbidden {
		t.Fatalf("missing OTP status = %d, want 403", rw.Code)
	}
}

// --- session rotation / logout ---

func TestSessionRotationKeepsCSRFInSync(t *testing.T) {
	w := securityTestWeb(t)
	id, csrf := loginSession(t, w, "")
	if rw := postWeb(w, "/settings/2fa/start", id, csrf, url.Values{"password": {"test-password"}}, false, nil); rw.Code != http.StatusFound {
		t.Fatalf("start status = %d", rw.Code)
	}
	sess, _ := w.sessions.get(id)
	code, _ := totp.GenerateCode(sess.pendingSecret, w.nowTime())
	rw := postWeb(w, "/settings/2fa/enable", id, csrf, url.Values{"otp": {code}}, false, nil)
	if rw.Code != http.StatusOK {
		t.Fatalf("enable status = %d, body=%s", rw.Code, rw.Body.String())
	}
	cookies := rw.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("rotation cookies = %+v", cookies)
	}
	rotated, ok := w.sessions.get(cookies[0].Value)
	if !ok {
		t.Fatal("rotated session missing")
	}
	if w.sessions.valid(id) {
		t.Fatal("old session survived rotation")
	}
	if !strings.Contains(rw.Body.String(), rotated.csrf) {
		t.Fatal("response does not carry the rotated CSRF token")
	}
	if strings.Contains(rw.Body.String(), csrf) {
		t.Fatal("response still carries the revoked CSRF token")
	}
}

func TestLogoutRequiresCSRFAndDeletesSecureCookie(t *testing.T) {
	w := securityTestWeb(t)
	id, csrf := loginSession(t, w, "")
	other, _ := loginSession(t, w, "")

	rw := postWeb(w, "/logout", id, "", nil, false, nil)
	if rw.Code != http.StatusForbidden {
		t.Fatalf("logout without CSRF = %d, want 403", rw.Code)
	}
	if !w.sessions.valid(id) {
		t.Fatal("CSRF-less logout deleted the session")
	}

	rw = postWeb(w, "/logout", id, csrf, nil, false, func(r *http.Request) {
		r.TLS = &tls.ConnectionState{}
	})
	if rw.Code != http.StatusFound {
		t.Fatalf("logout status = %d", rw.Code)
	}
	cookies := rw.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("logout cookies = %+v", cookies)
	}
	cookie := cookies[0]
	if !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || !cookie.Secure || cookie.MaxAge != -1 {
		t.Fatalf("logout cookie attributes = %+v", cookie)
	}
	if w.sessions.valid(id) {
		t.Fatal("logout did not delete the session")
	}
	if !w.sessions.valid(other) {
		t.Fatal("logout deleted another session")
	}
}

// --- template / frontend contract ---

func TestWebTemplatesCarryCSRF(t *testing.T) {
	for _, name := range []string{
		"layout.html", "settings.html", "agents.html", "credential_form.html",
		"certificate_new.html", "certificates.html", "two_factor.html",
	} {
		body, err := fs.ReadFile(templatesFS, "web/templates/"+name)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(body), `name="csrf"`) {
			t.Errorf("%s does not carry a csrf form field", name)
		}
	}
	layout, err := fs.ReadFile(templatesFS, "web/templates/layout.html")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(layout), `name="csrf-token"`) {
		t.Error("layout does not expose the csrf meta tag")
	}
}
