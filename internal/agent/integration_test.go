package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Flyinsky2004/oh-my-acme/internal/pki"
	"github.com/Flyinsky2004/oh-my-acme/internal/protocol"
)

// disableNginx makes the agent deterministic in tests: it never resolves or
// executes a real nginx/systemctl, even on a Linux CI host that has them.
func disableNginx(a *Agent) {
	a.nginxInstalled = false
	a.nginxPath = ""
	a.systemctlPath = ""
	a.runFn = func(context.Context, string, []string) ([]byte, error) {
		return nil, errors.New("unexpected command execution")
	}
}

// TestDeployOverMTLS starts a real Agent over mTLS and pushes a certificate
// from the perspective of the server (which presents a client cert signed by
// the shared internal CA). It exercises the full deploy handler including
// chain/key verification and file installation.
func TestDeployOverMTLS(t *testing.T) {
	dir := t.TempDir()
	ca, err := pki.NewCA("test-ca")
	if err != nil {
		t.Fatal(err)
	}
	// Agent server identity (what the agent presents to the server).
	agentID, err := ca.SignServerIdentity([]net.IP{net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	// Server's client identity (what the test "server" presents to the agent).
	serverClient, err := ca.SignServerClientIdentity()
	if err != nil {
		t.Fatal(err)
	}

	caPEM := ca.EncodeCA()
	writeF := func(p string, b []byte) {
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	certFile := filepath.Join(dir, "agent.crt")
	keyFile := filepath.Join(dir, "agent.key")
	caFile := filepath.Join(dir, "ca.crt")
	serverCAFile := filepath.Join(dir, "server-ca.crt")
	certDir := filepath.Join(dir, "certs")
	writeF(certFile, agentID.CertPEM)
	writeF(keyFile, agentID.KeyPEM)
	writeF(caFile, caPEM)
	writeF(serverCAFile, caPEM)
	_ = os.MkdirAll(certDir, 0o700)

	cfg := Config{
		Listen: "127.0.0.1", Port: 0,
		CertDir: certDir, LogDir: dir,
		CertFile: certFile, KeyFile: keyFile, CAFile: caFile, ServerCAFile: serverCAFile,
	}
	a, err := New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	disableNginx(a)
	tlsCfg, err := a.TLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(a.Handler())
	srv.TLS = tlsCfg
	srv.StartTLS()
	defer srv.Close()

	// TEST client: presents the server's client cert; trusts the CA.
	clientCert, err := tls.X509KeyPair(serverClient.CertPEM, serverClient.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{clientCert},
			RootCAs:      poolOf(ca.Cert),
			MinVersion:   tls.VersionTLS12,
		}},
	}

	chain := newTestChain(t, leafSpec{})
	req := chain.request("example.com")
	req.CertificateID = "cert1"
	req.VersionID = "ver1"
	body, _ := json.Marshal(req)
	hreq, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL+protocol.AgentAPIPrefix+"/deploy", bytes.NewReader(body))
	hreq.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(hreq)
	if err != nil {
		t.Fatalf("deploy request: %v", err)
	}
	defer resp.Body.Close()
	var out protocol.DeployResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if !out.Success {
		t.Fatalf("deploy not successful: %+v", out)
	}
	if strings.TrimSpace(out.Log) == "" {
		t.Fatal("expected deploy log")
	}
	// The files should have been written with the correct permissions.
	for _, n := range []string{"cert.pem", "ca.pem", "fullchain.pem", "privkey.pem"} {
		if _, err := os.Stat(filepath.Join(certDir, "example.com", n)); err != nil {
			t.Fatalf("expected %s: %v", n, err)
		}
	}
	fi, _ := os.Stat(filepath.Join(certDir, "example.com", "privkey.pem"))
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("privkey mode = %o, want 600", fi.Mode().Perm())
	}

	// Without a client cert the agent must reject the connection at TLS layer.
	badClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: poolOf(ca.Cert), MinVersion: tls.VersionTLS12,
	}}}
	if _, err := badClient.Get(srv.URL + protocol.AgentAPIPrefix + "/health"); err == nil {
		t.Fatal("expected TLS rejection for client without cert")
	}
}

func poolOf(cert *x509.Certificate) *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(cert)
	return p
}

func TestHandleDeployIgnoresCancelledRequestContext(t *testing.T) {
	dir := t.TempDir()
	a, err := New(Config{
		CertDir:      filepath.Join(dir, "certs"),
		CertFile:     filepath.Join(dir, "agent.crt"),
		KeyFile:      filepath.Join(dir, "agent.key"),
		ServerCAFile: filepath.Join(dir, "ca.crt"),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	disableNginx(a)

	chain := newTestChain(t, leafSpec{})
	req := chain.request("example.com")
	req.CertificateID = "cert1"
	req.VersionID = "ver1"
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	httpReq := httptest.NewRequest(http.MethodPost, protocol.AgentAPIPrefix+"/deploy", bytes.NewReader(body)).WithContext(ctx)
	rw := httptest.NewRecorder()
	a.handleDeploy(rw, httpReq)
	if rw.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 body=%s", rw.Code, rw.Body.String())
	}
	var out protocol.DeployResponse
	if err := json.NewDecoder(rw.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if !out.Success {
		t.Fatalf("deploy not successful: %+v", out)
	}
	if strings.TrimSpace(out.Log) == "" {
		t.Fatal("expected deploy log on cancelled request context")
	}
}
