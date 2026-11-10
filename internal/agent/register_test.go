package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Flyinsky2004/oh-my-acme/internal/pki"
	"github.com/Flyinsky2004/oh-my-acme/internal/protocol"
)

func newRegisterCA(t *testing.T) *pki.CA {
	t.Helper()
	ca, err := pki.NewCA("test-ca")
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

func testServerIdentity(t *testing.T, ca *pki.CA) (*pki.KeyPair, tls.Certificate) {
	t.Helper()
	kp, err := ca.SignServerIdentity([]net.IP{net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(kp.CertPEM, kp.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return kp, cert
}

func startTLSServer(t *testing.T, cert tls.Certificate, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func parseCSRForTest(t *testing.T, csrPEM []byte) *x509.CertificateRequest {
	t.Helper()
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		t.Fatal("CSR is not PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

func parseCertForTest(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	cert, err := parseSingleCertificatePEM(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func makeRegisterResponse(ca *pki.CA, csrPEM []byte, agentID string) (protocol.RegisterResponse, error) {
	kp, err := ca.SignAgentCSR(csrPEM, []net.IP{net.ParseIP("127.0.0.1")})
	if err != nil {
		return protocol.RegisterResponse{}, err
	}
	leaf, err := parseSingleCertificatePEM(kp.CertPEM)
	if err != nil {
		return protocol.RegisterResponse{}, err
	}
	return protocol.RegisterResponse{
		AgentID:     agentID,
		CertPEM:     string(kp.CertPEM),
		CAPEM:       string(ca.EncodeCA()),
		ServerCAPEM: string(ca.EncodeCA()),
		ExpiresAt:   leaf.NotAfter.Format(time.RFC3339),
	}, nil
}

func signingHandler(ca *pki.CA, calls *atomic.Int32, token *atomic.Value) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if calls != nil {
			calls.Add(1)
		}
		var req protocol.RegisterRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if token != nil {
			token.Store(req.Token)
		}
		resp, err := makeRegisterResponse(ca, []byte(req.CSR), "agent-1")
		if err != nil {
			http.Error(w, "sign failed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

func newTestIdentity(t *testing.T) (keyPEM, csrPEM []byte) {
	t.Helper()
	keyPEM, csrPEM, err := GenerateKeyAndCSR("test-agent")
	if err != nil {
		t.Fatal(err)
	}
	return keyPEM, csrPEM
}

func TestRegisterPinnedFingerprintFormats(t *testing.T) {
	ca := newRegisterCA(t)
	kp, cert := testServerIdentity(t, ca)
	srv := startTLSServer(t, cert, signingHandler(ca, nil, nil))
	keyPEM, csrPEM := newTestIdentity(t)

	raw := strings.TrimPrefix(kp.Fingerprint(), "SHA256:")
	colon := make([]string, 0, len(raw)/2)
	for i := 0; i < len(raw); i += 2 {
		colon = append(colon, raw[i:i+2])
	}
	formats := []string{
		kp.Fingerprint(),
		raw,
		strings.ToUpper(raw),
		strings.ToLower("SHA256:" + raw),
		strings.Join(colon, ":"),
		"SHA256:" + strings.Join(colon, ":"),
	}
	for _, fp := range formats {
		reg, err := RegisterWithKey(context.Background(), srv.URL, "token", "", "agent", 9123, csrPEM, keyPEM, fp)
		if err != nil {
			t.Fatalf("fingerprint %q: %v", fp, err)
		}
		if reg.AgentID != "agent-1" {
			t.Fatalf("agent id = %q", reg.AgentID)
		}
		if reg.ServerIP != "127.0.0.1" {
			t.Fatalf("server ip = %q", reg.ServerIP)
		}
		if err := validateIdentityMaterial(reg, keyPEM); err != nil {
			t.Fatalf("identity invalid: %v", err)
		}
	}
}

func TestRegisterPinnedFingerprintRejectsWrongLeafWithoutSendingToken(t *testing.T) {
	realCA := newRegisterCA(t)
	realKP, _ := testServerIdentity(t, realCA)
	attackerCA := newRegisterCA(t)
	_, attackerCert := testServerIdentity(t, attackerCA)

	var calls atomic.Int32
	var gotToken atomic.Value
	srv := startTLSServer(t, attackerCert, signingHandler(attackerCA, &calls, &gotToken))
	keyPEM, csrPEM := newTestIdentity(t)

	_, err := RegisterWithKey(context.Background(), srv.URL, "secret-token", "", "agent", 9123, csrPEM, keyPEM, realKP.Fingerprint())
	if err == nil {
		t.Fatal("expected pin mismatch")
	}
	if calls.Load() != 0 {
		t.Fatalf("handler received %d requests; token must not be sent", calls.Load())
	}
	if gotToken.Load() != nil {
		t.Fatalf("handler received token %q", gotToken.Load())
	}
}

func TestRegisterPinnedFingerprintChecksOnlyLeaf(t *testing.T) {
	realCA := newRegisterCA(t)
	realKP, _ := testServerIdentity(t, realCA)
	attackerCA := newRegisterCA(t)
	attackerKP, attackerCert := testServerIdentity(t, attackerCA)

	// The server presents an attacker leaf followed by the real leaf. A pin
	// must match PeerCertificates[0] only.
	chain := attackerCert
	chain.Certificate = append(chain.Certificate, realKP.Cert.Raw)

	keyPEM, csrPEM := newTestIdentity(t)

	var calls atomic.Int32
	srv := startTLSServer(t, chain, signingHandler(realCA, &calls, nil))
	if _, err := RegisterWithKey(context.Background(), srv.URL, "token", "", "agent", 9123, csrPEM, keyPEM, realKP.Fingerprint()); err == nil {
		t.Fatal("expected pin mismatch against attacker leaf")
	}
	if calls.Load() != 0 {
		t.Fatalf("handler received %d requests", calls.Load())
	}

	// Pinning the attacker leaf (the actual first certificate) succeeds even
	// though the real leaf is appended to the chain.
	if _, err := RegisterWithKey(context.Background(), srv.URL, "token", "", "agent", 9123, csrPEM, keyPEM, attackerKP.Fingerprint()); err != nil {
		t.Fatalf("pin of leaf[0] failed: %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("handler calls = %d, want 1", calls.Load())
	}
}

func TestParsePinnedFingerprintFormats(t *testing.T) {
	digest := strings.Repeat("ab", 32)
	groups := make([]string, 32)
	for i := range groups {
		groups[i] = digest[i*2 : i*2+2]
	}
	colon := strings.Join(groups, ":")
	want, err := hex.DecodeString(digest)
	if err != nil {
		t.Fatal(err)
	}
	valid := []string{
		digest,
		strings.ToUpper(digest),
		"SHA256:" + digest,
		"sha256:" + strings.ToUpper(digest),
		colon,
		"SHA256:" + colon,
		" " + digest,
		digest + " ",
		"\t" + digest + "\r\n",
		"  SHA256:" + colon + "\n",
	}
	for _, fp := range valid {
		got, err := parsePinnedFingerprint(fp)
		if err != nil {
			t.Fatalf("%q: %v", fp, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%q: wrong digest", fp)
		}
	}
	if got, err := parsePinnedFingerprint(""); err != nil || got != nil {
		t.Fatalf("empty fingerprint = %v, %v", got, err)
	}
	invalid := []string{
		" ",
		"\t\r\n",
		"SHA256:",
		"SHA-256:" + digest,
		digest[:63],
		digest + "a",
		strings.Join(groups[:31], ":"),
		strings.Join(append(append([]string{}, groups...), "ab"), ":"),
		strings.Replace(colon, ":", "::", 1),
		strings.Replace(colon, groups[0], "a", 1),
		strings.Replace(colon, groups[0], "abc", 1),
		strings.Repeat("zz", 32),
		strings.Replace(digest, digest[:2], digest[:2]+" ", 1),
	}
	for _, fp := range invalid {
		if _, err := parsePinnedFingerprint(fp); err == nil {
			t.Fatalf("%q accepted", fp)
		}
	}
}

func TestRegistrationEndpointRejectsInsecureOrMalformedURL(t *testing.T) {
	invalid := []string{
		"http://127.0.0.1:9444",
		"https://user:pass@127.0.0.1:9444",
		"https:///v1",
		"not a url",
		"https://127.0.0.1:bad",
		"https://127.0.0.1:9444/path?q=1",
		"https://127.0.0.1:9444/path#fragment",
		"https:opaque",
		"",
	}
	for _, raw := range invalid {
		if _, err := registrationEndpoint(raw); err == nil {
			t.Fatalf("%q accepted", raw)
		}
	}
	got, err := registrationEndpoint("https://127.0.0.1:9444/")
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://127.0.0.1:9444/v1/register" {
		t.Fatalf("endpoint = %q", got)
	}
}

func TestRegisterWithoutPinUsesSystemVerification(t *testing.T) {
	ca := newRegisterCA(t)
	_, cert := testServerIdentity(t, ca)
	var calls atomic.Int32
	srv := startTLSServer(t, cert, signingHandler(ca, &calls, nil))
	keyPEM, csrPEM := newTestIdentity(t)

	if _, err := RegisterWithKey(context.Background(), srv.URL, "token", "", "agent", 9123, csrPEM, keyPEM, ""); err == nil {
		t.Fatal("expected normal PKI verification to reject the test CA")
	}
	if calls.Load() != 0 {
		t.Fatalf("handler received %d requests", calls.Load())
	}
}

func TestRegisterDoesNotFollowRedirect(t *testing.T) {
	ca := newRegisterCA(t)
	kp, cert := testServerIdentity(t, ca)
	keyPEM, csrPEM := newTestIdentity(t)

	for _, status := range []int{http.StatusFound, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		for _, scheme := range []string{"https", "http"} {
			t.Run(fmt.Sprintf("%d_%s", status, scheme), func(t *testing.T) {
				var targetCalls atomic.Int32
				var targetToken atomic.Value
				targetHandler := func(w http.ResponseWriter, r *http.Request) {
					targetCalls.Add(1)
					var req protocol.RegisterRequest
					_ = json.NewDecoder(r.Body).Decode(&req)
					targetToken.Store(req.Token)
					http.Error(w, "must not be reached", http.StatusInternalServerError)
				}
				var targetURL string
				if scheme == "https" {
					target := startTLSServer(t, cert, targetHandler)
					targetURL = target.URL
				} else {
					target := httptest.NewServer(http.HandlerFunc(targetHandler))
					t.Cleanup(target.Close)
					targetURL = target.URL
				}
				redirect := startTLSServer(t, cert, func(w http.ResponseWriter, r *http.Request) {
					http.Redirect(w, r, targetURL+protocol.ControlAPIPrefix+"/register", status)
				})
				_, err := RegisterWithKey(context.Background(), redirect.URL, "secret-token", "", "agent", 9123, csrPEM, keyPEM, kp.Fingerprint())
				if !errors.Is(err, errRegistrationRedirect) {
					t.Fatalf("err = %v, want redirect rejection", err)
				}
				if targetCalls.Load() != 0 {
					t.Fatalf("redirect target received %d requests", targetCalls.Load())
				}
				if got := targetToken.Load(); got != nil {
					t.Fatalf("redirect target received token %q", got)
				}
			})
		}
	}

	// A direct HTTP endpoint is rejected before any request is sent.
	var httpCalls atomic.Int32
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httpCalls.Add(1)
	}))
	t.Cleanup(plain.Close)
	if _, err := RegisterWithKey(context.Background(), plain.URL, "secret-token", "", "agent", 9123, csrPEM, keyPEM, kp.Fingerprint()); err == nil {
		t.Fatal("expected http URL rejection")
	}
	if httpCalls.Load() != 0 {
		t.Fatalf("http endpoint received %d requests", httpCalls.Load())
	}
}

func TestRegisterRejectsOversizedResponse(t *testing.T) {
	ca := newRegisterCA(t)
	kp, cert := testServerIdentity(t, ca)
	srv := startTLSServer(t, cert, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(bytes.Repeat([]byte("a"), maxRegisterResponseBytes+1))
	})
	keyPEM, csrPEM := newTestIdentity(t)
	_, err := RegisterWithKey(context.Background(), srv.URL, "token", "", "agent", 9123, csrPEM, keyPEM, kp.Fingerprint())
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("err = %v", err)
	}
}

func TestRegisterRejectsTruncatedResponse(t *testing.T) {
	ca := newRegisterCA(t)
	kp, cert := testServerIdentity(t, ca)
	srv := startTLSServer(t, cert, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1000")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("short"))
	})
	keyPEM, csrPEM := newTestIdentity(t)
	_, err := RegisterWithKey(context.Background(), srv.URL, "token", "", "agent", 9123, csrPEM, keyPEM, kp.Fingerprint())
	if err == nil || !strings.Contains(err.Error(), "read register response") {
		t.Fatalf("err = %v", err)
	}
}

func TestRegisterErrorDoesNotEchoResponseBody(t *testing.T) {
	ca := newRegisterCA(t)
	kp, cert := testServerIdentity(t, ca)
	const token = "super-secret-token"
	srv := startTLSServer(t, cert, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "rejected "+token, http.StatusForbidden)
	})
	keyPEM, csrPEM := newTestIdentity(t)
	_, err := RegisterWithKey(context.Background(), srv.URL, token, "", "agent", 9123, csrPEM, keyPEM, kp.Fingerprint())
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), token) {
		t.Fatalf("error leaks token: %v", err)
	}
	if !strings.Contains(err.Error(), "403") {
		t.Fatalf("error should include status: %v", err)
	}
}

func signCSRWithTemplate(t *testing.T, ca *pki.CA, csr *x509.CertificateRequest, usage []x509.ExtKeyUsage, notBefore, notAfter time.Time, isCA bool) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               csr.Subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           usage,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}
	if isCA {
		tmpl.KeyUsage |= x509.KeyUsageCertSign
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, csr.PublicKey, ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func registerAndSaveTo(t *testing.T, dir, serverURL, requestedAgentID string, keyPEM, csrPEM []byte, fp string) error {
	t.Helper()
	cfg := Config{
		CertFile:     filepath.Join(dir, "agent.crt"),
		KeyFile:      filepath.Join(dir, "agent.key"),
		ServerCAFile: filepath.Join(dir, "ca.crt"),
		CAFile:       filepath.Join(dir, "ca.crt"),
	}
	reg, err := RegisterWithKey(context.Background(), serverURL, "token", requestedAgentID, "agent", 9123, csrPEM, keyPEM, fp)
	if err != nil {
		return err
	}
	return SaveIdentity(cfg, reg, keyPEM)
}

func assertNoIdentityFiles(t *testing.T, dir string) {
	t.Helper()
	for _, name := range []string{"agent.crt", "agent.key", "ca.crt"} {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Fatalf("%s was written after a failed registration", name)
		}
	}
}

func TestRegisterRejectsInvalidResponse(t *testing.T) {
	realCA := newRegisterCA(t)
	realKP, cert := testServerIdentity(t, realCA)
	attackerCA := newRegisterCA(t)
	keyPEM, csrPEM := newTestIdentity(t)
	csr := parseCSRForTest(t, csrPEM)
	otherKeyPEM, otherCSRPEM := newTestIdentity(t)
	_ = otherKeyPEM
	otherCSR := parseCSRForTest(t, otherCSRPEM)

	now := time.Now()
	validUsage := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	clientUsage := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	validCert := signCSRWithTemplate(t, realCA, csr, validUsage, now.Add(-time.Hour), now.Add(24*time.Hour), false)
	otherCert := signCSRWithTemplate(t, realCA, otherCSR, validUsage, now.Add(-time.Hour), now.Add(24*time.Hour), false)
	attackerCert := signCSRWithTemplate(t, attackerCA, csr, validUsage, now.Add(-time.Hour), now.Add(24*time.Hour), false)
	clientCert := signCSRWithTemplate(t, realCA, csr, clientUsage, now.Add(-time.Hour), now.Add(24*time.Hour), false)
	expiredCert := signCSRWithTemplate(t, realCA, csr, validUsage, now.Add(-2*time.Hour), now.Add(-time.Hour), false)
	futureCert := signCSRWithTemplate(t, realCA, csr, validUsage, now.Add(time.Hour), now.Add(2*time.Hour), false)
	caCert := signCSRWithTemplate(t, realCA, csr, validUsage, now.Add(-time.Hour), now.Add(24*time.Hour), true)

	base := func() protocol.RegisterResponse {
		return protocol.RegisterResponse{
			AgentID:     "agent-1",
			CertPEM:     string(validCert),
			CAPEM:       string(realCA.EncodeCA()),
			ServerCAPEM: string(realCA.EncodeCA()),
			ExpiresAt:   parseCertForTest(t, validCert).NotAfter.Format(time.RFC3339),
		}
	}

	cases := []struct {
		name             string
		requestedAgentID string
		mutate           func(*protocol.RegisterResponse)
	}{
		{name: "missing agent id", mutate: func(r *protocol.RegisterResponse) { r.AgentID = "" }},
		{name: "agent id mismatch", requestedAgentID: "expected", mutate: func(*protocol.RegisterResponse) {}},
		{name: "cert from another key", mutate: func(r *protocol.RegisterResponse) { r.CertPEM = string(otherCert) }},
		{name: "wrong CA", mutate: func(r *protocol.RegisterResponse) { r.CertPEM = string(attackerCert) }},
		{name: "wrong usage", mutate: func(r *protocol.RegisterResponse) { r.CertPEM = string(clientCert) }},
		{name: "expired", mutate: func(r *protocol.RegisterResponse) { r.CertPEM = string(expiredCert) }},
		{name: "not yet valid", mutate: func(r *protocol.RegisterResponse) { r.CertPEM = string(futureCert) }},
		{name: "certificate is CA", mutate: func(r *protocol.RegisterResponse) { r.CertPEM = string(caCert) }},
		{name: "cert trailing data", mutate: func(r *protocol.RegisterResponse) { r.CertPEM += "garbage" }},
		{name: "cert two blocks", mutate: func(r *protocol.RegisterResponse) { r.CertPEM += string(validCert) }},
		{name: "cert leading garbage", mutate: func(r *protocol.RegisterResponse) { r.CertPEM = "garbage" + r.CertPEM }},
		{name: "cert bad block before valid", mutate: func(r *protocol.RegisterResponse) {
			r.CertPEM = "-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----\n" + r.CertPEM
		}},
		{name: "cert headers", mutate: func(r *protocol.RegisterResponse) {
			r.CertPEM = strings.Replace(r.CertPEM, "-----\n", "-----\nProc-Type: 4,ENCRYPTED\n\n", 1)
		}},
		{name: "empty cert", mutate: func(r *protocol.RegisterResponse) { r.CertPEM = "" }},
		{name: "empty ca", mutate: func(r *protocol.RegisterResponse) { r.CAPEM = "" }},
		{name: "ca leading garbage", mutate: func(r *protocol.RegisterResponse) { r.CAPEM = "garbage" + r.CAPEM }},
		{name: "ca bad block before valid", mutate: func(r *protocol.RegisterResponse) {
			r.CAPEM = "-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----\n" + r.CAPEM
		}},
		{name: "ca headers", mutate: func(r *protocol.RegisterResponse) {
			r.CAPEM = strings.Replace(r.CAPEM, "-----\n", "-----\nProc-Type: 4,ENCRYPTED\n\n", 1)
		}},
		{name: "ca not a CA", mutate: func(r *protocol.RegisterResponse) { r.CAPEM = string(validCert) }},
		{name: "empty server ca", mutate: func(r *protocol.RegisterResponse) { r.ServerCAPEM = "" }},
		{name: "server ca not a CA", mutate: func(r *protocol.RegisterResponse) { r.ServerCAPEM = string(validCert) }},
		{name: "server ca mismatch", mutate: func(r *protocol.RegisterResponse) { r.ServerCAPEM = string(attackerCA.EncodeCA()) }},
		{name: "expires_at mismatch", mutate: func(r *protocol.RegisterResponse) { r.ExpiresAt = now.Add(time.Hour).Format(time.RFC3339) }},
		{name: "expires_at invalid", mutate: func(r *protocol.RegisterResponse) { r.ExpiresAt = "not-a-time" }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := startTLSServer(t, cert, func(w http.ResponseWriter, r *http.Request) {
				var req protocol.RegisterRequest
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					http.Error(w, "bad request", http.StatusBadRequest)
					return
				}
				resp := base()
				tc.mutate(&resp)
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(resp)
			})
			dir := t.TempDir()
			err := registerAndSaveTo(t, dir, srv.URL, tc.requestedAgentID, keyPEM, csrPEM, realKP.Fingerprint())
			if err == nil {
				t.Fatal("expected registration failure")
			}
			assertNoIdentityFiles(t, dir)
		})
	}
}

func TestRegisterAcceptsValidResponseAndSavesIdentity(t *testing.T) {
	ca := newRegisterCA(t)
	kp, cert := testServerIdentity(t, ca)
	srv := startTLSServer(t, cert, signingHandler(ca, nil, nil))
	keyPEM, csrPEM := newTestIdentity(t)
	dir := t.TempDir()
	if err := registerAndSaveTo(t, dir, srv.URL, "", keyPEM, csrPEM, kp.Fingerprint()); err != nil {
		t.Fatalf("register: %v", err)
	}
	for _, name := range []string{"agent.crt", "agent.key", "ca.crt"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("%s missing: %v", name, err)
		}
	}
	keyInfo, err := os.Stat(filepath.Join(dir, "agent.key"))
	if err != nil {
		t.Fatal(err)
	}
	if keyInfo.Mode().Perm() != 0o600 {
		t.Fatalf("key mode = %o", keyInfo.Mode().Perm())
	}
}

func TestSaveIdentityRollsBackOnRenameFailure(t *testing.T) {
	ca := newRegisterCA(t)
	keyPEM, csrPEM := newTestIdentity(t)
	resp, err := makeRegisterResponse(ca, csrPEM, "agent-1")
	if err != nil {
		t.Fatal(err)
	}
	reg := &Registration{AgentID: resp.AgentID, CertPEM: []byte(resp.CertPEM), CAPEM: []byte(resp.CAPEM), ServerCAPEM: []byte(resp.ServerCAPEM)}

	dir := t.TempDir()
	cfg := Config{
		CertFile:     filepath.Join(dir, "agent.crt"),
		KeyFile:      filepath.Join(dir, "agent.key"),
		ServerCAFile: filepath.Join(dir, "ca.crt"),
		CAFile:       filepath.Join(dir, "ca.crt"),
	}
	old := map[string]string{
		cfg.CertFile:     "old-cert",
		cfg.KeyFile:      "old-key",
		cfg.ServerCAFile: "old-ca",
	}
	for path, content := range old {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	writeFilesAtomicRenameHook = func(index int) error {
		if index == 1 {
			return errors.New("injected rename failure")
		}
		return nil
	}
	defer func() { writeFilesAtomicRenameHook = nil }()
	if err := SaveIdentity(cfg, reg, keyPEM); err == nil {
		t.Fatal("expected failure")
	}
	for path, content := range old {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != content {
			t.Fatalf("%s = %q, want %q", path, got, content)
		}
	}
}

func TestSaveIdentityRollbackDoesNotCreateFiles(t *testing.T) {
	ca := newRegisterCA(t)
	keyPEM, csrPEM := newTestIdentity(t)
	resp, err := makeRegisterResponse(ca, csrPEM, "agent-1")
	if err != nil {
		t.Fatal(err)
	}
	reg := &Registration{AgentID: resp.AgentID, CertPEM: []byte(resp.CertPEM), CAPEM: []byte(resp.CAPEM), ServerCAPEM: []byte(resp.ServerCAPEM)}
	dir := t.TempDir()
	cfg := Config{
		CertFile:     filepath.Join(dir, "agent.crt"),
		KeyFile:      filepath.Join(dir, "agent.key"),
		ServerCAFile: filepath.Join(dir, "ca.crt"),
		CAFile:       filepath.Join(dir, "ca.crt"),
	}
	writeFilesAtomicRenameHook = func(index int) error {
		if index == 0 {
			return errors.New("injected rename failure")
		}
		return nil
	}
	defer func() { writeFilesAtomicRenameHook = nil }()
	if err := SaveIdentity(cfg, reg, keyPEM); err == nil {
		t.Fatal("expected failure")
	}
	assertNoIdentityFiles(t, dir)
}

func TestSaveIdentityAndConfigRollsBackConfigFailure(t *testing.T) {
	ca := newRegisterCA(t)
	keyPEM, csrPEM := newTestIdentity(t)
	resp, err := makeRegisterResponse(ca, csrPEM, "agent-1")
	if err != nil {
		t.Fatal(err)
	}
	reg := &Registration{AgentID: resp.AgentID, CertPEM: []byte(resp.CertPEM), CAPEM: []byte(resp.CAPEM), ServerCAPEM: []byte(resp.ServerCAPEM)}

	dir := t.TempDir()
	cfg := Config{
		CertFile:     filepath.Join(dir, "agent.crt"),
		KeyFile:      filepath.Join(dir, "agent.key"),
		ServerCAFile: filepath.Join(dir, "ca.crt"),
		CAFile:       filepath.Join(dir, "ca.crt"),
	}
	configPath := filepath.Join(dir, "config.json")
	old := map[string]string{
		cfg.CertFile:     "old-cert",
		cfg.KeyFile:      "old-key",
		cfg.ServerCAFile: "old-ca",
		configPath:       `{"token":"old"}`,
	}
	for path, content := range old {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	next := Config{AgentID: resp.AgentID, Token: ""}
	// Identity writes are cert, key, ca; config is index 3.
	writeFilesAtomicRenameHook = func(index int) error {
		if index == 3 {
			return errors.New("injected config failure")
		}
		return nil
	}
	defer func() { writeFilesAtomicRenameHook = nil }()
	if err := SaveIdentityAndConfig(cfg, reg, keyPEM, configPath, next); err == nil {
		t.Fatal("expected failure")
	}
	for path, content := range old {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != content {
			t.Fatalf("%s = %q, want %q", path, got, content)
		}
	}
}

func TestSaveIdentityRollbackFailureKeepsBackup(t *testing.T) {
	ca := newRegisterCA(t)
	keyPEM, csrPEM := newTestIdentity(t)
	resp, err := makeRegisterResponse(ca, csrPEM, "agent-1")
	if err != nil {
		t.Fatal(err)
	}
	reg := &Registration{AgentID: resp.AgentID, CertPEM: []byte(resp.CertPEM), CAPEM: []byte(resp.CAPEM), ServerCAPEM: []byte(resp.ServerCAPEM)}
	dir := t.TempDir()
	cfg := Config{
		CertFile:     filepath.Join(dir, "agent.crt"),
		KeyFile:      filepath.Join(dir, "agent.key"),
		ServerCAFile: filepath.Join(dir, "ca.crt"),
		CAFile:       filepath.Join(dir, "ca.crt"),
	}
	old := map[string]string{
		cfg.CertFile:     "old-cert",
		cfg.KeyFile:      "old-key",
		cfg.ServerCAFile: "old-ca",
	}
	for path, content := range old {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	var keptBackup string
	writeFilesAtomicRenameHook = func(index int) error {
		if index == 1 {
			return errors.New("injected promotion failure")
		}
		return nil
	}
	identityRestoreRenameHook = func(target, backup string) error {
		if target == cfg.CertFile {
			keptBackup = backup
			return errors.New("injected restore failure")
		}
		return nil
	}
	defer func() {
		writeFilesAtomicRenameHook = nil
		identityRestoreRenameHook = nil
	}()

	err = SaveIdentity(cfg, reg, keyPEM)
	if err == nil {
		t.Fatal("expected failure")
	}
	if keptBackup == "" {
		t.Fatal("rollback did not attempt to restore the promoted file")
	}
	if !strings.Contains(err.Error(), keptBackup) {
		t.Fatalf("error does not report the kept backup %q: %v", keptBackup, err)
	}
	backupData, err := os.ReadFile(keptBackup)
	if err != nil {
		t.Fatalf("kept backup missing: %v", err)
	}
	if string(backupData) != "old-cert" {
		t.Fatalf("kept backup = %q", backupData)
	}
	for _, path := range []string{cfg.KeyFile, cfg.ServerCAFile} {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != old[path] {
			t.Fatalf("%s = %q, want %q", path, got, old[path])
		}
	}
}

func TestSaveIdentityAndConfigSuccess(t *testing.T) {
	ca := newRegisterCA(t)
	keyPEM, csrPEM := newTestIdentity(t)
	resp, err := makeRegisterResponse(ca, csrPEM, "agent-1")
	if err != nil {
		t.Fatal(err)
	}
	reg := &Registration{AgentID: resp.AgentID, CertPEM: []byte(resp.CertPEM), CAPEM: []byte(resp.CAPEM), ServerCAPEM: []byte(resp.ServerCAPEM)}
	dir := t.TempDir()
	cfg := Config{
		CertFile:     filepath.Join(dir, "agent.crt"),
		KeyFile:      filepath.Join(dir, "agent.key"),
		ServerCAFile: filepath.Join(dir, "ca.crt"),
		CAFile:       filepath.Join(dir, "ca.crt"),
	}
	configPath := filepath.Join(dir, "config.json")
	for _, path := range []string{cfg.CertFile, cfg.KeyFile, cfg.ServerCAFile, configPath} {
		if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	next := Config{AgentID: resp.AgentID, Token: ""}
	if err := SaveIdentityAndConfig(cfg, reg, keyPEM, configPath, next); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".bak-") || strings.Contains(entry.Name(), ".tmp-") {
			t.Fatalf("leftover transaction file %q", entry.Name())
		}
	}
	configData, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	var got Config
	if err := json.Unmarshal(configData, &got); err != nil {
		t.Fatal(err)
	}
	if got.AgentID != resp.AgentID || got.Token != "" {
		t.Fatalf("config = %+v", got)
	}
}

func TestSaveIdentityRejectsMismatchedKeyOrCA(t *testing.T) {
	ca := newRegisterCA(t)
	keyPEM, csrPEM := newTestIdentity(t)
	resp, err := makeRegisterResponse(ca, csrPEM, "agent-1")
	if err != nil {
		t.Fatal(err)
	}
	otherKeyPEM, _ := newTestIdentity(t)
	attackerCA := newRegisterCA(t)
	dir := t.TempDir()
	cfg := Config{
		CertFile:     filepath.Join(dir, "agent.crt"),
		KeyFile:      filepath.Join(dir, "agent.key"),
		ServerCAFile: filepath.Join(dir, "ca.crt"),
		CAFile:       filepath.Join(dir, "ca.crt"),
	}
	base := &Registration{AgentID: resp.AgentID, CertPEM: []byte(resp.CertPEM), CAPEM: []byte(resp.CAPEM), ServerCAPEM: []byte(resp.ServerCAPEM)}
	for _, tc := range []struct {
		name string
		reg  *Registration
		key  []byte
	}{
		{name: "wrong key", reg: base, key: otherKeyPEM},
		{name: "wrong ca", reg: &Registration{AgentID: base.AgentID, CertPEM: base.CertPEM, CAPEM: attackerCA.EncodeCA(), ServerCAPEM: base.ServerCAPEM}, key: keyPEM},
		{name: "wrong server ca", reg: &Registration{AgentID: base.AgentID, CertPEM: base.CertPEM, CAPEM: base.CAPEM, ServerCAPEM: attackerCA.EncodeCA()}, key: keyPEM},
		{name: "bad cert", reg: &Registration{AgentID: base.AgentID, CertPEM: []byte("not pem"), CAPEM: base.CAPEM, ServerCAPEM: base.ServerCAPEM}, key: keyPEM},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := SaveIdentity(cfg, tc.reg, tc.key); err == nil {
				t.Fatal("expected validation failure")
			}
			assertNoIdentityFiles(t, dir)
		})
	}
}

func TestRegisterOldAPIStillWorks(t *testing.T) {
	ca := newRegisterCA(t)
	kp, cert := testServerIdentity(t, ca)
	srv := startTLSServer(t, cert, signingHandler(ca, nil, nil))
	keyPEM, csrPEM := newTestIdentity(t)
	reg, err := Register(context.Background(), srv.URL, "token", "", "agent", 9123, csrPEM, kp.Fingerprint())
	if err != nil {
		t.Fatal(err)
	}
	if err := validateIdentityMaterial(reg, keyPEM); err != nil {
		t.Fatal(err)
	}
}

func TestRegisterRejectsBadLocalMaterial(t *testing.T) {
	ca := newRegisterCA(t)
	kp, cert := testServerIdentity(t, ca)
	srv := startTLSServer(t, cert, signingHandler(ca, nil, nil))
	keyPEM, csrPEM := newTestIdentity(t)
	otherKeyPEM, _ := newTestIdentity(t)
	if _, err := RegisterWithKey(context.Background(), srv.URL, "token", "", "agent", 9123, csrPEM, otherKeyPEM, kp.Fingerprint()); err == nil {
		t.Fatal("expected key/CSR mismatch")
	}
	if _, err := RegisterWithKey(context.Background(), srv.URL, "token", "", "agent", 9123, []byte("not pem"), keyPEM, kp.Fingerprint()); err == nil {
		t.Fatal("expected bad CSR")
	}
	leadingCSR := append([]byte("garbage"), csrPEM...)
	if _, err := RegisterWithKey(context.Background(), srv.URL, "token", "", "agent", 9123, leadingCSR, keyPEM, kp.Fingerprint()); err == nil {
		t.Fatal("expected leading garbage in CSR to be rejected")
	}
	badFirstCSR := append([]byte("-----BEGIN CERTIFICATE REQUEST-----\n!!!\n-----END CERTIFICATE REQUEST-----\n"), csrPEM...)
	if _, err := RegisterWithKey(context.Background(), srv.URL, "token", "", "agent", 9123, badFirstCSR, keyPEM, kp.Fingerprint()); err == nil {
		t.Fatal("expected malformed first CSR block to be rejected")
	}
	leadingKey := append([]byte("garbage"), keyPEM...)
	if _, err := RegisterWithKey(context.Background(), srv.URL, "token", "", "agent", 9123, csrPEM, leadingKey, kp.Fingerprint()); err == nil {
		t.Fatal("expected leading garbage in private key to be rejected")
	}
}
