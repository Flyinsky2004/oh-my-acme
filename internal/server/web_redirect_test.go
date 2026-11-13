package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestRedirectHelperHTMXAndPlain covers the two navigation contracts of the
// shared redirect helper: a plain form post gets 302 + Location, while an HTMX
// request gets HX-Redirect on a non-3xx, body-less response so htmx performs a
// full browser navigation instead of swapping the target page into the
// triggering element.
func TestRedirectHelperHTMXAndPlain(t *testing.T) {
	w := &Web{}
	for _, tt := range []struct {
		name       string
		htmx       bool
		wantStatus int
	}{
		{name: "plain form", wantStatus: http.StatusFound},
		{name: "htmx request", htmx: true, wantStatus: http.StatusNoContent},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/agents/agent-1/delete", nil)
			if tt.htmx {
				r.Header.Set("HX-Request", "true")
			}
			rw := httptest.NewRecorder()
			w.redirect(rw, r, "/agents")
			if rw.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", rw.Code, tt.wantStatus)
			}
			if tt.htmx {
				if got := rw.Header().Get("HX-Redirect"); got != "/agents" {
					t.Fatalf("HX-Redirect = %q, want /agents", got)
				}
				if got := rw.Header().Get("Location"); got != "" {
					t.Fatalf("HTMX response carries Location %q", got)
				}
				if rw.Body.Len() != 0 {
					t.Fatalf("HTMX response body = %q, want empty", rw.Body.String())
				}
				return
			}
			if got := rw.Header().Get("Location"); got != "/agents" {
				t.Fatalf("Location = %q, want /agents", got)
			}
			if got := rw.Header().Get("HX-Redirect"); got != "" {
				t.Fatalf("plain response carries HX-Redirect %q", got)
			}
		})
	}
}
