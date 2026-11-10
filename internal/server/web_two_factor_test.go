package server

import (
	"crypto/tls"
	"encoding/base32"
	"encoding/json"
	"image/png"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Flyinsky2004/oh-my-acme/internal/domain"
	"github.com/Flyinsky2004/oh-my-acme/internal/store"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

func twoFactorRequest(w *Web, method, path, id string, form url.Values) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if id != "" {
		r.AddCookie(&http.Cookie{Name: "omc_session", Value: id})
	}
	rw := httptest.NewRecorder()
	w.Handler().ServeHTTP(rw, r)
	return rw
}

func securityValues(w *Web, id string) url.Values {
	s, _ := w.sessions.get(id)
	return url.Values{"csrf": {s.csrf}, "password": {"test-password"}}
}

func TestTwoFactorEnrollmentAndDisable(t *testing.T) {
	w := loginHistoryWeb(t)
	if err := w.srv.setAdminPassword("admin", "test-password"); err != nil {
		t.Fatal(err)
	}
	id := w.sessions.create("admin")
	other := w.sessions.create("admin")
	// Authentication and CSRF are both mandatory.
	if rw := twoFactorRequest(w, "GET", "/settings/2fa", "", nil); rw.Code != 302 {
		t.Fatal("public security page")
	}
	if rw := twoFactorRequest(w, "POST", "/settings/2fa/start", id, url.Values{"password": {"test-password"}}); rw.Code != 403 {
		t.Fatal("missing CSRF accepted")
	}
	form := securityValues(w, id)
	form.Set("password", "wrong")
	twoFactorRequest(w, "POST", "/settings/2fa/start", id, form)
	s, _ := w.sessions.get(id)
	if s.pendingSecret != "" {
		t.Fatal("enrollment started without password")
	}
	form.Set("password", "test-password")
	rw := twoFactorRequest(w, "POST", "/settings/2fa/start", id, form)
	if rw.Code != 302 {
		t.Fatalf("start: %d %s", rw.Code, rw.Body)
	}
	s, _ = w.sessions.get(id)
	if s.pendingSecret == "" || w.srv.getAdmin().TwoFactor.Enabled {
		t.Fatal("enabled before confirmation or missing pending secret")
	}
	if rw := twoFactorRequest(w, "GET", "/settings/2fa/qr", other, nil); rw.Code != 404 {
		t.Fatal("QR shared across sessions")
	}
	rw = twoFactorRequest(w, "GET", "/settings/2fa/qr", id, nil)
	if rw.Code != 200 || rw.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("QR not served privately")
	}
	image, err := png.Decode(rw.Body)
	if err != nil || image.Bounds().Dx() != 256 {
		t.Fatalf("bad QR image: %v", err)
	}
	key, err := otp.NewKeyFromURL(provisioningURI("admin", s.pendingSecret))
	if err != nil || key.Secret() != s.pendingSecret || key.Issuer() != "oh-my-acme" {
		t.Fatal("wrong provisioning key")
	}
	form.Set("otp", "invalid")
	twoFactorRequest(w, "POST", "/settings/2fa/enable", id, form)
	if w.srv.getAdmin().TwoFactor.Enabled {
		t.Fatal("invalid code enabled 2FA")
	}
	code, _ := totp.GenerateCode(s.pendingSecret, time.Now())
	form.Set("otp", code)
	rw = twoFactorRequest(w, "POST", "/settings/2fa/enable", id, form)
	if rw.Code != 200 {
		t.Fatalf("enable: %d %s", rw.Code, rw.Body)
	}
	if !w.srv.getAdmin().TwoFactor.Enabled || w.sessions.valid(id) || w.sessions.valid(other) {
		t.Fatal("activation/session revocation failed")
	}
	codes := regexp.MustCompile(`[a-f0-9]{5}(?:-[a-f0-9]{5}){3}`).FindAllString(rw.Body.String(), -1)
	if len(codes) != 10 || len(rw.Result().Cookies()) != 1 {
		t.Fatal("recovery codes or rotated session missing")
	}
	id = rw.Result().Cookies()[0].Value
	stateJSON, _ := json.Marshal(w.srv.st.State())
	if strings.Contains(string(stateJSON), s.pendingSecret) || w.srv.getAdmin().TwoFactor.Secret != "" || w.srv.getAdmin().TwoFactor.EncryptedSecret == "" {
		t.Fatal("enrollment persisted an unencrypted binding secret")
	}
	if strings.Contains(string(stateJSON), codes[0]) || strings.Contains(string(stateJSON), strings.ReplaceAll(codes[0], "-", "")) {
		t.Fatal("plaintext recovery code persisted")
	}
	rw = twoFactorRequest(w, "GET", "/settings/2fa", id, nil)
	if strings.Contains(rw.Body.String(), codes[0]) || strings.Contains(rw.Body.String(), s.pendingSecret) {
		t.Fatal("secrets redisplayed")
	}
	// A recovery code must not bypass password reauthentication when disabling.
	form = securityValues(w, id)
	form.Set("otp", codes[0])
	form.Set("password", "wrong")
	twoFactorRequest(w, "POST", "/settings/2fa/disable", id, form)
	if !w.srv.getAdmin().TwoFactor.Enabled || len(w.srv.getAdmin().TwoFactor.RecoveryHashes) != 10 {
		t.Fatal("password bypass or recovery code consumed on wrong password")
	}
	form.Set("password", "test-password")
	rw = twoFactorRequest(w, "POST", "/settings/2fa/disable", id, form)
	if rw.Code != 302 || w.srv.getAdmin().TwoFactor.Enabled || w.sessions.valid(id) || w.srv.getAdmin().TwoFactor.Secret != "" || w.srv.getAdmin().TwoFactor.EncryptedSecret != "" {
		t.Fatal("disable failed")
	}
}

func enableTestFactor(t *testing.T, w *Web) (string, []string) {
	t.Helper()
	if err := w.srv.setAdminPassword("admin", "test-password"); err != nil {
		t.Fatal(err)
	}
	secret := "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	codes, hashes, err := newRecoveryCodes()
	if err != nil {
		t.Fatal(err)
	}
	if err := w.saveTwoFactor(domain.AdminTwoFactor{Enabled: true, Secret: secret, RecoveryHashes: hashes}); err != nil {
		t.Fatal(err)
	}
	return secret, codes
}

func TestTwoFactorLoginAndPersistentReplayProtection(t *testing.T) {
	w := loginHistoryWeb(t)
	secret, codes := enableTestFactor(t, w)
	code, _ := totp.GenerateCode(secret, time.Now())
	for _, tt := range []struct {
		password, code string
		success        bool
	}{
		{"test-password", "", false}, {"test-password", "bad", false},
		{"wrong", code, false}, {"test-password", code, true},
		{"test-password", code, false}, {"test-password", codes[0], true},
		{"test-password", codes[0], false},
	} {
		rw := twoFactorRequest(w, "POST", "/login", "", url.Values{"username": {"admin"}, "password": {tt.password}, "otp": {tt.code}})
		if got := rw.Code == 302 && len(rw.Result().Cookies()) == 1; got != tt.success {
			t.Fatalf("login success=%v, want %v (%d)", got, tt.success, rw.Code)
		}
		if records := w.srv.st.State().AdminLogins; records[0].Success != tt.success {
			t.Fatal("incorrect login history result")
		}
	}
	reopened, err := store.Open(filepath.Dir(w.srv.st.StatePath()))
	if err != nil {
		t.Fatal(err)
	}
	w.srv.st = reopened
	if ok, err := w.consumeSecondFactor(codes[0]); err != nil || ok {
		t.Fatal("recovery code replayed after restart")
	}
	if ok, err := w.consumeSecondFactor(code); err != nil || ok {
		t.Fatal("TOTP replayed after restart")
	}
	if !w.srv.getAdmin().TwoFactor.Enabled {
		t.Fatal("2FA lost after restart")
	}
}

func TestTwoFactorConcurrentCodeUse(t *testing.T) {
	w := loginHistoryWeb(t)
	_, codes := enableTestFactor(t, w)
	var wg sync.WaitGroup
	results := make(chan bool, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rw := twoFactorRequest(w, "POST", "/login", "", url.Values{"username": {"admin"}, "password": {"test-password"}, "otp": {codes[0]}})
			results <- rw.Code == 302
		}()
	}
	wg.Wait()
	close(results)
	successes := 0
	for ok := range results {
		if ok {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("one-time code accepted %d times", successes)
	}
}

func TestTOTPSkewAndRateLimit(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	now := time.Unix(1800000000, 0)
	for _, delta := range []int64{-2, -1, 0, 1, 2} {
		code, _ := totp.GenerateCode(secret, now.Add(time.Duration(delta)*30*time.Second))
		step, ok := matchingTOTPStep(secret, code, now, 0)
		want := delta >= -1 && delta <= 1
		if ok != want {
			t.Fatalf("skew %d accepted=%v", delta, ok)
		}
		if ok {
			if _, replay := matchingTOTPStep(secret, code, now, step); replay {
				t.Fatal("replay accepted")
			}
		}
	}
	w := loginHistoryWeb(t)
	for i := 0; i < 10; i++ {
		if !w.allowSensitiveAttempt(httptest.NewRecorder()) {
			t.Fatal("limited too early")
		}
	}
	rw := httptest.NewRecorder()
	if w.allowSensitiveAttempt(rw) || rw.Code != 429 || rw.Header().Get("Retry-After") == "" {
		t.Fatal("rate limit missing")
	}
	w.authWindow = time.Now().Add(-time.Minute)
	if !w.allowSensitiveAttempt(httptest.NewRecorder()) {
		t.Fatal("limiter never resets")
	}
}

func TestTwoFactorExpiryAndSaveFailure(t *testing.T) {
	w := loginHistoryWeb(t)
	id := w.sessions.create("admin")
	w.sessions.setPending(id, "JBSWY3DPEHPK3PXP")
	w.sessions.mu.Lock()
	s := w.sessions.sessions[id]
	s.pendingUntil = time.Now().Add(-time.Second)
	w.sessions.sessions[id] = s
	w.sessions.mu.Unlock()
	rw := twoFactorRequest(w, "GET", "/settings/2fa/qr", id, nil)
	if rw.Code != 404 {
		t.Fatal("expired QR still available")
	}
	form := securityValues(w, id)
	form.Set("otp", "123456")
	twoFactorRequest(w, "POST", "/settings/2fa/enable", id, form)
	if w.srv.getAdmin().TwoFactor.Enabled {
		t.Fatal("expired setup activated")
	}
	// Force an atomic-save error and verify activation is rolled back in memory.
	if err := os.Mkdir(w.srv.st.StatePath()+".tmp", 0700); err != nil {
		t.Fatal(err)
	}
	err := w.saveTwoFactor(domain.AdminTwoFactor{Enabled: true, Secret: "secret"})
	if err == nil || w.srv.getAdmin().TwoFactor.Enabled {
		t.Fatal("failed save enabled 2FA")
	}
}

func TestTOTPReferenceVector(t *testing.T) {
	// RFC 6238 Appendix B, SHA-1 at Unix 59: 94287082 truncated to six digits.
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
	if step, ok := matchingTOTPStep(secret, "287082", time.Unix(59, 0), 0); !ok || step != 1 {
		t.Fatal("Google Authenticator TOTP parameters do not match the RFC vector")
	}
}

func TestSecondFactorSaveFailureDoesNotCreateSession(t *testing.T) {
	w := loginHistoryWeb(t)
	_, codes := enableTestFactor(t, w)
	if err := os.Mkdir(w.srv.st.StatePath()+".tmp", 0700); err != nil {
		t.Fatal(err)
	}
	rw := twoFactorRequest(w, "POST", "/login", "", url.Values{"username": {"admin"}, "password": {"test-password"}, "otp": {codes[0]}})
	if rw.Code != 500 || len(rw.Result().Cookies()) != 0 {
		t.Fatal("session issued without persisting second factor")
	}
	if len(w.srv.getAdmin().TwoFactor.RecoveryHashes) != 10 {
		t.Fatal("recovery code lost on failed save")
	}
}

func TestSessionCookieHTTPS(t *testing.T) {
	w := loginHistoryWeb(t)
	w.srv.cfg.TrustedProxies = []string{"127.0.0.1"}
	for _, tt := range []struct {
		name, peer, proto string
		tls, secure       bool
	}{
		{name: "direct TLS", peer: "192.0.2.1:1234", tls: true, secure: true},
		{name: "trusted TLS proxy", peer: "127.0.0.1:1234", proto: "https", secure: true},
		{name: "spoofed TLS", peer: "192.0.2.1:1234", proto: "https"},
		{name: "plain HTTP", peer: "127.0.0.1:1234"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = tt.peer
			r.Header.Set("X-Forwarded-Proto", tt.proto)
			if tt.tls {
				r.TLS = &tls.ConnectionState{}
			}
			rw := httptest.NewRecorder()
			w.sessionCookieAndSet(rw, r, "test-session")
			cookies := rw.Result().Cookies()
			if len(cookies) != 1 || cookies[0].Secure != tt.secure {
				t.Fatalf("wrong Secure flag: %+v", cookies)
			}
		})
	}
}
