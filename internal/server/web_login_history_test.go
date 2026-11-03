package server

import (
	"fmt"
	"log/slog"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Flyinsky2004/oh-my-acme/internal/store"
)

func TestLoginClientIP(t *testing.T) {
	for _, tt := range []struct {
		name, peer, forwarded, real, want string
		trusted                           []string
	}{
		{name: "untrusted spoof", peer: "192.0.2.10:3000", forwarded: "203.0.113.1", real: "203.0.113.2", want: "192.0.2.10"},
		{name: "trusted chain", peer: "127.0.0.1:3000", forwarded: "198.51.100.99, 203.0.113.1, 10.0.0.2", trusted: []string{"127.0.0.1", "10.0.0.0/8"}, want: "203.0.113.1"},
		{name: "real ip", peer: "127.0.0.1:3000", real: "203.0.113.2", trusted: []string{"127.0.0.1"}, want: "203.0.113.2"},
		{name: "ipv6", peer: "[::1]:3000", forwarded: "2001:db8::12", trusted: []string{"::1"}, want: "2001:db8::12"},
		{name: "malformed", peer: "127.0.0.1:3000", forwarded: "invalid", trusted: []string{"127.0.0.1"}, want: "127.0.0.1"},
		{name: "mapped ipv4", peer: "[::ffff:192.0.2.10]:3000", want: "192.0.2.10"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/login", nil)
			r.RemoteAddr = tt.peer
			r.Header.Set("X-Forwarded-For", tt.forwarded)
			r.Header.Set("X-Real-IP", tt.real)
			if got := loginClientIP(r, tt.trusted); got != tt.want {
				t.Fatalf("got %s, want %s", got, tt.want)
			}
		})
	}
}

func loginHistoryWeb(t *testing.T) *Web {
	t.Helper()
	t.Setenv("TWO_FACTOR_ENCRYPTION_KEY", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	w, err := NewWeb(&Server{st: st, log: slog.Default()})
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func TestAdminLoginRotationAndPersistence(t *testing.T) {
	w := loginHistoryWeb(t)
	for i := 0; i < 60; i++ {
		r := httptest.NewRequest("POST", "/login", nil)
		r.PostForm = url.Values{"browser_metadata": {`{"platform":"Linux","timezone":"Asia/Shanghai"}`}}
		if err := w.recordAdminLogin(r, fmt.Sprint(i), true); err != nil {
			t.Fatal(err)
		}
	}
	reopened, err := store.Open(strings.TrimSuffix(w.srv.st.StatePath(), "/state.json"))
	if err != nil {
		t.Fatal(err)
	}
	records := reopened.State().AdminLogins
	if len(records) != 50 || records[0].Username != "59" || records[49].Username != "10" {
		t.Fatalf("incorrect rotated records: %+v", records)
	}
	if records[0].Time.IsZero() || len(records[0].Fingerprint) != 64 {
		t.Fatal("missing timestamp/fingerprint")
	}
	var html strings.Builder
	if err := w.tmpl.ExecuteTemplate(&html, "settings", map[string]any{"AdminLogins": records}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(html.String(), records[0].Fingerprint) || !strings.Contains(html.String(), "管理员登录记录") {
		t.Fatal("history not rendered")
	}
}

func TestAdminLoginFlow(t *testing.T) {
	w := loginHistoryWeb(t)
	if err := w.srv.setAdminPassword("admin", "test-password"); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		password string
		success  bool
	}{{"wrong", false}, {"test-password", true}} {
		form := url.Values{"username": {"admin"}, "password": {tt.password}, "browser_metadata": {`{"platform":"MacIntel","screen":"1920x1080x24"}`}}
		r := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh) Chrome/130.0.0.0 Safari/537.36")
		rw := httptest.NewRecorder()
		w.Handler().ServeHTTP(rw, r)
		records := w.srv.st.State().AdminLogins
		if len(records) == 0 || records[0].Success != tt.success || records[0].Device != "电脑 / macOS" || records[0].Browser != "Chrome 130.0.0.0" {
			t.Fatalf("unexpected records: %+v", records)
		}
		if tt.success {
			if rw.Code != 302 || len(rw.Result().Cookies()) != 1 || !w.sessions.valid(rw.Result().Cookies()[0].Value) {
				t.Fatal("successful login did not create a session")
			}
		} else if len(rw.Result().Cookies()) != 0 {
			t.Fatal("failed login created cookie")
		}
	}
	// Existing auth must also protect the records.
	rw := httptest.NewRecorder()
	w.Handler().ServeHTTP(rw, httptest.NewRequest("GET", "/settings", nil))
	if rw.Code != 302 || rw.Header().Get("Location") != "/login" {
		t.Fatal("settings exposed without authentication")
	}
}

func TestAdminLoginFingerprintFallbackAndCanonicalization(t *testing.T) {
	w := loginHistoryWeb(t)
	fingerprints := []string{}
	for _, raw := range []string{"", "not-json", `{"platform":"Linux","timezone":"UTC"}`, `{"timezone":"UTC", "platform":"Linux"}`, `{"platform":"Linux","timezone":"Asia/Shanghai"}`} {
		r := httptest.NewRequest("POST", "/login", nil)
		r.PostForm = url.Values{"browser_metadata": {raw}}
		if err := w.recordAdminLogin(r, "admin", true); err != nil {
			t.Fatal(err)
		}
		fingerprints = append(fingerprints, w.srv.st.State().AdminLogins[0].Fingerprint)
	}
	if fingerprints[0] != fingerprints[1] || fingerprints[2] != fingerprints[3] || fingerprints[3] == fingerprints[4] || fingerprints[0] == fingerprints[2] {
		t.Fatal("fingerprint normalization or fallback failed")
	}
}
