package agent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Flyinsky2004/oh-my-acme/internal/protocol"
)

// Registration bundles the local identity material produced during
// registration so the CLI can persist it.
type Registration struct {
	AgentID string
	CertPEM []byte
	CAPEM   []byte // the internal CA (trust anchor for the server's client cert)
}

// GenerateKeyAndCSR produces the agent's own EC key (kept locally) and a CSR
// for a server-identity certificate, so the agent never sends its private key
// off the machine.
func GenerateKeyAndCSR(name string) (keyPEM []byte, csrPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: "oh-my-acme-agent:" + name},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}, key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	csrPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	return keyPEM, csrPEM, nil
}

// Register submits the CSR to the server's control port. When a CA fingerprint
// was supplied at install time it is pinned via TLS VerifyConnection, so an
// impostor cannot capture the one-time token — this is how the agent confirms
// it is talking to the real server without depending on any third-party CA.
func Register(ctx context.Context, serverURL, token, agentID, name string, port int, csrPEM []byte, caFingerprint string) (*Registration, error) {
	req := protocol.RegisterRequest{
		Token: token, AgentID: agentID, Name: name, Port: port,
		CSR: string(csrPEM), Version: Version,
		GOOS: runtime.GOOS, GOARCH: runtime.GOARCH,
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	u, err := url.JoinPath(strings.TrimRight(serverURL, "/"), protocol.ControlAPIPrefix, "register")
	if err != nil {
		return nil, err
	}

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFingerprint != "" {
		want := normalizeFingerprint(caFingerprint)
		tlsCfg.InsecureSkipVerify = true
		tlsCfg.VerifyConnection = func(cs tls.ConnectionState) error {
			for _, c := range cs.PeerCertificates {
				if sha256Fingerprint(c) == want {
					return nil
				}
			}
			return errors.New("server certificate does not match pinned CA fingerprint")
		}
	}

	hc := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsCfg}}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("register request: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("register failed (%d): %s", resp.StatusCode, truncate(string(respBody), 256))
	}

	var reg protocol.RegisterResponse
	if err := json.Unmarshal(respBody, &reg); err != nil {
		return nil, err
	}
	return &Registration{AgentID: reg.AgentID, CertPEM: []byte(reg.CertPEM), CAPEM: []byte(reg.ServerCAPEM)}, nil
}

// SaveIdentity writes the agent's identity certificate and the CA trust anchor
// to their configured files, using the key the agent generated locally.
func SaveIdentity(cfg Config, reg *Registration, keyPEM []byte) error {
	if err := os.MkdirAll(filepath.Dir(cfg.CertFile), 0o700); err != nil {
		return err
	}
	if err := writeFileMode(cfg.CertFile, reg.CertPEM, 0o644); err != nil {
		return err
	}
	if err := writeFileMode(cfg.KeyFile, keyPEM, 0o600); err != nil {
		return err
	}
	if err := writeFileMode(cfg.ServerCAFile, reg.CAPEM, 0o644); err != nil {
		return err
	}
	if cfg.CAFile != "" {
		if err := writeFileMode(cfg.CAFile, reg.CAPEM, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func writeFileMode(p string, b []byte, mode os.FileMode) error {
	return os.WriteFile(p, b, mode)
}

func normalizeFingerprint(fp string) string {
	fp = strings.TrimSpace(fp)
	fp = strings.TrimPrefix(strings.ToUpper(fp), "SHA256:")
	return strings.ToLower(strings.ReplaceAll(fp, ":", ""))
}

func sha256Fingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}
