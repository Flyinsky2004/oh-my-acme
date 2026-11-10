package server

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// Exercise the application's read deadline on a real local connection, rather
// than only checking that SetReadDeadline was called on a recorder.
func TestIncompleteLoginBodyTimesOut(t *testing.T) {
	for _, contentType := range []string{"application/x-www-form-urlencoded", "application/json", "multipart/form-data; boundary=test", "text/plain", ""} {
		t.Run(contentType, func(t *testing.T) { assertIncompleteLoginBodyTimesOut(t, contentType) })
	}
}

func assertIncompleteLoginBodyTimesOut(t *testing.T, contentType string) {
	t.Helper()
	w := securityTestWeb(t)
	w.authReadTimeout = 25 * time.Millisecond
	server := httptest.NewServer(w.Handler())
	defer server.Close()
	address := server.Listener.Addr().String()
	conn, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintf(conn, "POST /login HTTP/1.1\r\nHost: %s\r\nContent-Type: %s\r\nContent-Length: 128\r\n\r\nusername=admin&password=", address, contentType); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodPost})
	if err != nil {
		t.Fatalf("incomplete request was not terminated with a response: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusBadRequest && response.StatusCode != http.StatusRequestTimeout {
		t.Fatalf("timeout status = %d", response.StatusCode)
	}
	if !w.authMu.TryLock() {
		t.Fatal("timed out request retained the authentication lock")
	}
	w.authMu.Unlock()
	w.sessions.mu.Lock()
	count := len(w.sessions.sessions)
	w.sessions.mu.Unlock()
	if count != 0 {
		t.Fatal("incomplete login created a session")
	}
}

func TestBodyLimitsApplyBeforeContentTypeParsing(t *testing.T) {
	w := securityTestWeb(t)
	for _, contentType := range []string{"application/json", "multipart/form-data; boundary=test", "text/plain", ""} {
		t.Run(contentType, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(strings.Repeat("x", maxLoginBody+1)))
			req.Header.Set("Content-Type", contentType)
			response := httptest.NewRecorder()
			w.Handler().ServeHTTP(response, req)
			if response.Code != http.StatusRequestEntityTooLarge {
				t.Fatalf("oversized %q body returned %d", contentType, response.Code)
			}
		})
	}
	id, csrf := loginSession(t, w, "")
	response := postWeb(w, "/settings/2fa/start", id, csrf, url.Values{"padding": {strings.Repeat("x", maxTwoFactorBody+1)}}, true, nil)
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized 2FA body returned %d", response.Code)
	}
}

func TestTwoFactorSlowBodiesDoNotHoldAuthMu(t *testing.T) {
	for _, path := range []string{"/settings/2fa/start", "/settings/2fa/enable", "/settings/2fa/disable"} {
		t.Run(path, func(t *testing.T) {
			w := securityTestWeb(t)
			id, csrf := loginSession(t, w, "")
			body := newBlockingBody([]byte(url.Values{"csrf": {csrf}, "password": {"test-password"}}.Encode()))
			request := httptest.NewRequest(http.MethodPost, path, body)
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			request.AddCookie(&http.Cookie{Name: w.cookie, Value: id})
			done := make(chan struct{})
			go func() { w.Handler().ServeHTTP(httptest.NewRecorder(), request); close(done) }()
			<-body.started
			acquired := w.authMu.TryLock()
			if acquired {
				w.authMu.Unlock()
			}
			close(body.release)
			<-done
			if !acquired {
				t.Fatal("slow 2FA body held the authentication lock")
			}
		})
	}
}
