package server

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/Flyinsky2004/oh-my-acme/internal/domain"
	"github.com/Flyinsky2004/oh-my-acme/internal/pki"
	"github.com/Flyinsky2004/oh-my-acme/internal/protocol"
	"github.com/Flyinsky2004/oh-my-acme/internal/store"
)

func newControlTestServer(t *testing.T) (*Server, *store.Store, *pki.CA) {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ca, err := pki.NewCA("control-test-ca")
	if err != nil {
		t.Fatal(err)
	}
	srv := &Server{
		st:  st,
		ca:  ca,
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	return srv, st, ca
}

func controlTestCSR(t *testing.T, cn string) (keyPEM, csrPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: "oh-my-acme-agent:" + cn},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	csrPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	return keyPEM, csrPEM
}

func doRegisterFrom(srv *Server, body []byte, remoteAddr string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, protocol.ControlAPIPrefix+"/register", bytes.NewReader(body))
	req.RemoteAddr = remoteAddr
	req.Header.Set("Content-Type", "application/json")
	rw := httptest.NewRecorder()
	srv.ControlHandler().ServeHTTP(rw, req)
	return rw
}

func doRegister(srv *Server, body []byte) *httptest.ResponseRecorder {
	return doRegisterFrom(srv, body, "203.0.113.9:12345")
}

func registerBody(t *testing.T, token, agentID, name string, port int, csrPEM []byte) []byte {
	t.Helper()
	body, err := json.Marshal(protocol.RegisterRequest{
		Token: token, AgentID: agentID, Name: name, Port: port, CSR: string(csrPEM),
	})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func controlTestPublicKeysEqual(a, b any) bool {
	aDER, err := x509.MarshalPKIXPublicKey(a)
	if err != nil {
		return false
	}
	bDER, err := x509.MarshalPKIXPublicKey(b)
	if err != nil {
		return false
	}
	return bytes.Equal(aDER, bDER)
}

func decodeRegisterResponse(t *testing.T, rw *httptest.ResponseRecorder) protocol.RegisterResponse {
	t.Helper()
	var resp protocol.RegisterResponse
	if err := json.Unmarshal(rw.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v (body %s)", err, rw.Body.String())
	}
	return resp
}

func TestHandleRegisterConsumesTokenAndWritesAgent(t *testing.T) {
	srv, st, ca := newControlTestServer(t)
	token, agentID, err := srv.CreateAgentToken("agent-name")
	if err != nil {
		t.Fatal(err)
	}
	_, csrPEM := controlTestCSR(t, "agent")
	rw := doRegister(srv, registerBody(t, token, "", "my-agent", 9123, csrPEM))
	if rw.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rw.Code, rw.Body.String())
	}
	resp := decodeRegisterResponse(t, rw)
	if resp.AgentID != agentID {
		t.Fatalf("agent id = %q, want %q", resp.AgentID, agentID)
	}
	leaf, err := pki.ParseCertificatePEM([]byte(resp.CertPEM))
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	csrBlock, _ := pem.Decode(csrPEM)
	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !controlTestPublicKeysEqual(leaf.PublicKey, csr.PublicKey) {
		t.Fatal("returned certificate does not match the CSR")
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Fatalf("returned certificate does not verify: %v", err)
	}
	if resp.ExpiresAt != leaf.NotAfter.Format(time.RFC3339) {
		t.Fatalf("expires_at = %q", resp.ExpiresAt)
	}

	state := st.State()
	rec := state.Tokens[token]
	if rec == nil || rec.UsedAt.IsZero() {
		t.Fatal("token was not consumed")
	}
	agent := state.Agents[agentID]
	if agent == nil {
		t.Fatal("agent was not written")
	}
	if agent.Address != "203.0.113.9" || agent.Port != 9123 || agent.Name != "my-agent" {
		t.Fatalf("agent = %+v", agent)
	}
	if !agent.CertExpiresAt.Equal(leaf.NotAfter) {
		t.Fatalf("cert expiry = %v, want %v", agent.CertExpiresAt, leaf.NotAfter)
	}

	// Replay must be rejected and must not create a second agent.
	replay := doRegister(srv, registerBody(t, token, "", "replay", 9123, csrPEM))
	if replay.Code != http.StatusForbidden {
		t.Fatalf("replay status = %d", replay.Code)
	}
	if got := len(st.State().Agents); got != 1 {
		t.Fatalf("agents = %d, want 1", got)
	}
}

func TestHandleRegisterRejectsInvalidTokens(t *testing.T) {
	srv, st, _ := newControlTestServer(t)
	_, csrPEM := controlTestCSR(t, "agent")

	if err := st.Update(func(s *domain.State) error {
		s.Tokens["expired"] = &domain.TokenRecord{Token: "expired", AgentID: "agent-expired", ExpiresAt: time.Now().Add(-time.Minute)}
		s.Tokens["used"] = &domain.TokenRecord{Token: "used", AgentID: "agent-used", UsedAt: time.Now()}
		s.Tokens["bound"] = &domain.TokenRecord{Token: "bound", AgentID: "bound-agent", ExpiresAt: time.Now().Add(time.Minute)}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name    string
		token   string
		agentID string
	}{
		{name: "unknown", token: "missing"},
		{name: "expired", token: "expired"},
		{name: "used", token: "used"},
		{name: "binding mismatch", token: "bound", agentID: "other-agent"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rw := doRegister(srv, registerBody(t, tc.token, tc.agentID, "agent", 9123, csrPEM))
			if rw.Code != http.StatusForbidden {
				t.Fatalf("status = %d body=%s", rw.Code, rw.Body.String())
			}
		})
	}
	if got := len(st.State().Agents); got != 0 {
		t.Fatalf("agents = %d, want 0", got)
	}

	// A bound token with no requested id resolves to the bound id.
	rw := doRegister(srv, registerBody(t, "bound", "", "agent", 9123, csrPEM))
	if rw.Code != http.StatusOK {
		t.Fatalf("bound status = %d body=%s", rw.Code, rw.Body.String())
	}
	if resp := decodeRegisterResponse(t, rw); resp.AgentID != "bound-agent" {
		t.Fatalf("agent id = %q", resp.AgentID)
	}
}

func TestHandleRegisterRejectsInvalidInputWithoutConsumingToken(t *testing.T) {
	srv, st, _ := newControlTestServer(t)
	token, _, err := srv.CreateAgentToken("agent")
	if err != nil {
		t.Fatal(err)
	}
	_, csrPEM := controlTestCSR(t, "agent")

	for _, tc := range []struct {
		name string
		body []byte
	}{
		{name: "invalid csr", body: registerBody(t, token, "", "agent", 9123, []byte("not pem"))},
		{name: "negative port", body: registerBody(t, token, "", "agent", -1, csrPEM)},
		{name: "large port", body: registerBody(t, token, "", "agent", 70000, csrPEM)},
		{name: "control char in name", body: registerBody(t, token, "", "bad\x00name", 9123, csrPEM)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rw := doRegister(srv, tc.body)
			if rw.Code != http.StatusBadRequest {
				t.Fatalf("status = %d body=%s", rw.Code, rw.Body.String())
			}
		})
	}
	rec := st.State().Tokens[token]
	if rec == nil || !rec.UsedAt.IsZero() {
		t.Fatal("invalid request consumed the token")
	}
	if got := len(st.State().Agents); got != 0 {
		t.Fatalf("agents = %d", got)
	}
}

func TestHandleRegisterConcurrentSameTokenOnlyOnce(t *testing.T) {
	srv, st, _ := newControlTestServer(t)
	token, _, err := srv.CreateAgentToken("agent")
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
	if state.Tokens[token] == nil || state.Tokens[token].UsedAt.IsZero() {
		t.Fatal("token not consumed")
	}
}

func TestHandleRegisterDifferentCSRWinnerNotOverwritten(t *testing.T) {
	srv, st, _ := newControlTestServer(t)
	token, _, err := srv.CreateAgentToken("bound-name")
	if err != nil {
		t.Fatal(err)
	}

	type attempt struct {
		name       string
		remoteAddr string
		remoteIP   string
		port       int
		body       []byte
		csr        *x509.CertificateRequest
	}
	attempts := []attempt{
		{name: "winner-a", remoteAddr: "198.51.100.10:4000", remoteIP: "198.51.100.10", port: 9101},
		{name: "winner-b", remoteAddr: "198.51.100.11:4000", remoteIP: "198.51.100.11", port: 9102},
	}
	for i := range attempts {
		_, csrPEM := controlTestCSR(t, attempts[i].name)
		block, _ := pem.Decode(csrPEM)
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		attempts[i].csr = csr
		attempts[i].body = registerBody(t, token, "", attempts[i].name, attempts[i].port, csrPEM)
	}

	var ready sync.WaitGroup
	ready.Add(len(attempts))
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

	type result struct {
		index int
		rw    *httptest.ResponseRecorder
	}
	results := make(chan result, len(attempts))
	var wg sync.WaitGroup
	for i := range attempts {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results <- result{index: i, rw: doRegisterFrom(srv, attempts[i].body, attempts[i].remoteAddr)}
		}(i)
	}
	wg.Wait()
	close(results)

	winner := -1
	var winnerRecorder *httptest.ResponseRecorder
	for result := range results {
		switch result.rw.Code {
		case http.StatusOK:
			if winner != -1 {
				t.Fatal("more than one registration succeeded")
			}
			winner = result.index
			winnerRecorder = result.rw
		case http.StatusForbidden:
		default:
			t.Fatalf("unexpected status %d", result.rw.Code)
		}
	}
	if winner == -1 {
		t.Fatal("no registration succeeded")
	}
	resp := decodeRegisterResponse(t, winnerRecorder)
	leaf, err := pki.ParseCertificatePEM([]byte(resp.CertPEM))
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	if !controlTestPublicKeysEqual(leaf.PublicKey, attempts[winner].csr.PublicKey) {
		t.Fatal("winner's certificate does not match the winner's CSR")
	}
	state := st.State()
	if len(state.Agents) != 1 {
		t.Fatalf("agents = %d, want 1", len(state.Agents))
	}
	agent := state.Agents[resp.AgentID]
	if agent == nil {
		t.Fatal("winning agent missing")
	}
	if agent.Name != attempts[winner].name {
		t.Fatalf("agent name = %q, want %q", agent.Name, attempts[winner].name)
	}
	if agent.Address != attempts[winner].remoteIP {
		t.Fatalf("agent address = %q, want %q", agent.Address, attempts[winner].remoteIP)
	}
	if agent.Port != attempts[winner].port {
		t.Fatalf("agent port = %d, want %d", agent.Port, attempts[winner].port)
	}
	if !agent.CertExpiresAt.Equal(leaf.NotAfter) {
		t.Fatalf("agent cert expiry = %v, want %v", agent.CertExpiresAt, leaf.NotAfter)
	}
	if len(leaf.IPAddresses) != 1 || leaf.IPAddresses[0].String() != attempts[winner].remoteIP {
		t.Fatalf("certificate IP SAN = %v, want %s", leaf.IPAddresses, attempts[winner].remoteIP)
	}
	loser := 1 - winner
	if agent.Address == attempts[loser].remoteIP || agent.Port == attempts[loser].port {
		t.Fatal("loser overwrote the winner's agent record")
	}
	for _, ip := range leaf.IPAddresses {
		if ip.String() == attempts[loser].remoteIP {
			t.Fatal("certificate contains the loser's IP SAN")
		}
	}
}

func TestHandleRegisterPersistenceFailureDoesNotReturnIdentity(t *testing.T) {
	srv, st, _ := newControlTestServer(t)
	token, _, err := srv.CreateAgentToken("agent")
	if err != nil {
		t.Fatal(err)
	}
	_, csrPEM := controlTestCSR(t, "agent")
	body := registerBody(t, token, "", "agent", 9123, csrPEM)

	before, err := os.ReadFile(st.StatePath())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(st.StatePath()+".tmp", 0o700); err != nil {
		t.Fatal(err)
	}
	rw := doRegister(srv, body)
	if rw.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d body=%s", rw.Code, rw.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(rw.Body.Bytes(), &payload); err != nil {
		t.Fatalf("error body is not JSON: %v", err)
	}
	for _, field := range []string{"cert_pem", "agent_id", "server_ca_pem"} {
		if _, ok := payload[field]; ok {
			t.Fatalf("failure response contains %q", field)
		}
	}
	state := st.State()
	if rec := state.Tokens[token]; rec == nil || !rec.UsedAt.IsZero() {
		t.Fatal("failed registration consumed the token in memory")
	}
	if len(state.Agents) != 0 {
		t.Fatalf("agents = %d, want 0", len(state.Agents))
	}
	after, err := os.ReadFile(st.StatePath())
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("failed registration changed the primary state file")
	}

	if err := os.Remove(st.StatePath() + ".tmp"); err != nil {
		t.Fatal(err)
	}
	retry := doRegister(srv, body)
	if retry.Code != http.StatusOK {
		t.Fatalf("retry status = %d body=%s", retry.Code, retry.Body.String())
	}
	state = st.State()
	if rec := state.Tokens[token]; rec == nil || rec.UsedAt.IsZero() {
		t.Fatal("retry did not consume the token")
	}
	if len(state.Agents) != 1 {
		t.Fatalf("agents = %d, want 1", len(state.Agents))
	}
}
