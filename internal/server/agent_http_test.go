package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Flyinsky2004/oh-my-acme/internal/domain"
	"github.com/Flyinsky2004/oh-my-acme/internal/protocol"
	"github.com/Flyinsky2004/oh-my-acme/internal/store"
)

func testAgentAt(t *testing.T, target *httptest.Server) *domain.Agent {
	t.Helper()
	host, port, err := net.SplitHostPort(target.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	portN, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	return &domain.Agent{ID: "agent-test", Address: host, Port: portN}
}

func TestAgentEndpointsNeverRedirect(t *testing.T) {
	for _, endpoint := range []string{"deploy", "update", "health"} {
		for _, status := range []int{http.StatusMovedPermanently, http.StatusFound, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
			t.Run(endpoint+"/"+strconv.Itoa(status), func(t *testing.T) {
				var received atomic.Int32
				target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					received.Add(1)
					w.Write([]byte(`{"success":true}`))
				}))
				defer target.Close()
				source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if endpoint == "deploy" {
						body, _ := io.ReadAll(r.Body)
						if !strings.Contains(string(body), "private-key-fixture") {
							t.Error("deploy body not sent to intended endpoint")
						}
					}
					http.Redirect(w, r, target.URL+"/redirected", status)
				}))
				defer source.Close()
				pool := x509.NewCertPool()
				pool.AddCert(source.Certificate())
				pool.AddCert(target.Certificate())
				st, err := store.Open(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				agent := testAgentAt(t, source)
				if err := st.WithState(true, func(state *domain.State) error { state.Agents[agent.ID] = agent; return nil }); err != nil {
					t.Fatal(err)
				}
				srv := &Server{st: st, cliTLSCfg: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
				switch endpoint {
				case "deploy":
					_, err = srv.pushCert(context.Background(), agent, protocol.DeployRequest{PrivateKeyPEM: "private-key-fixture"})
				case "update":
					err = srv.updateAgent(context.Background(), agent.ID, "v1.2.3")
				case "health":
					err = srv.RefreshAgent(context.Background(), agent.ID)
				}
				if err == nil {
					t.Fatal("redirect accepted")
				}
				if received.Load() != 0 {
					t.Fatalf("redirect target received %d requests", received.Load())
				}
			})
		}
	}
}

func TestAgentResponseBoundsAndReadErrors(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
		wantError  bool
	}{
		{"valid", `{"success":true}`, http.StatusOK, false},
		{"over-limit", `{"log":"` + strings.Repeat("x", maxAgentResponseBytes) + `"}`, http.StatusOK, true},
		{"malformed", `{"success":`, http.StatusOK, true},
		{"trailing", `{"success":true}{"success":false}`, http.StatusOK, true},
		{"status", `{"success":true}`, http.StatusForbidden, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := &http.Response{StatusCode: tc.status, Body: io.NopCloser(strings.NewReader(tc.body))}
			var result protocol.DeployResponse
			err := decodeAgentResponse(resp, &result)
			if (err != nil) != tc.wantError {
				t.Fatalf("decode: %v", err)
			}
		})
	}
	var result protocol.DeployResponse
	err := decodeAgentResponse(&http.Response{StatusCode: 200, Body: io.NopCloser(agentBrokenResponse{})}, &result)
	if err == nil || !strings.Contains(err.Error(), "read agent response") {
		t.Fatalf("read error ignored: %v", err)
	}
}

type agentBrokenResponse struct{}

func (agentBrokenResponse) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
