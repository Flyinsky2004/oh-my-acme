package agent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"path"
	"runtime"
	"strings"
	"time"

	"github.com/Flyinsky2004/oh-my-acme/internal/protocol"
)

const (
	registerTimeout          = 15 * time.Second
	maxRegisterResponseBytes = 256 << 10
)

// errRegistrationRedirect is returned when the fixed registration endpoint
// answers with a redirect. Redirects are never followed: the one-time token is
// in the request body, and following a Location chosen by the peer could send
// it to a different host.
var errRegistrationRedirect = errors.New("registration endpoint redirected; refusing to follow")

// Registration bundles the local identity material produced during
// registration so the CLI can persist it.
type Registration struct {
	AgentID string
	CertPEM []byte
	// CAPEM is the issuing CA for the agent identity certificate. It is also
	// the legacy trust anchor written to both CA files when ServerCAPEM is
	// absent.
	CAPEM []byte
	// ServerCAPEM is the CA that signs the server's client certificate. When
	// empty, CAPEM is used (older servers returned one CA for both roles).
	ServerCAPEM []byte
	ServerIP    string // actual peer address used by the successful registration
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
//
// The fingerprint is the SHA-256 digest of the server's TLS leaf certificate.
// Register keeps the historical signature; use RegisterWithKey when the local
// private key is available so the response can also be checked against it.
func Register(ctx context.Context, serverURL, token, agentID, name string, port int, csrPEM []byte, caFingerprint string) (*Registration, error) {
	return RegisterWithKey(ctx, serverURL, token, agentID, name, port, csrPEM, nil, caFingerprint)
}

// RegisterWithKey is Register plus a check that the returned identity
// certificate matches the locally generated private key. Every field of the
// response is validated before the caller can persist anything.
func RegisterWithKey(ctx context.Context, serverURL, token, agentID, name string, port int, csrPEM, keyPEM []byte, caFingerprint string) (*Registration, error) {
	if strings.TrimSpace(token) == "" {
		return nil, errors.New("registration token is required")
	}
	endpoint, err := registrationEndpoint(serverURL)
	if err != nil {
		return nil, err
	}
	csr, err := parseCSR(csrPEM)
	if err != nil {
		return nil, err
	}
	var localPub any
	if len(keyPEM) > 0 {
		localPub, err = publicKeyFromPrivateKeyPEM(keyPEM)
		if err != nil {
			return nil, err
		}
		if !publicKeysEqual(localPub, csr.PublicKey) {
			return nil, errors.New("local private key does not match the CSR")
		}
	}
	pinned, err := parsePinnedFingerprint(caFingerprint)
	if err != nil {
		return nil, err
	}

	req := protocol.RegisterRequest{
		Token: token, AgentID: agentID, Name: name, Port: port,
		CSR: string(csrPEM), Version: Version,
		GOOS: runtime.GOOS, GOARCH: runtime.GOARCH,
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if pinned != nil {
		// A pin replaces public-PKI verification, but it must be checked
		// against the leaf only: a chain may append any extra certificate.
		tlsCfg.InsecureSkipVerify = true
		tlsCfg.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("server presented no TLS certificate")
			}
			if subtle.ConstantTimeCompare(certSHA256(cs.PeerCertificates[0]), pinned) != 1 {
				return errors.New("server TLS leaf certificate does not match the pinned fingerprint")
			}
			return nil
		}
	}

	hc := &http.Client{
		Timeout: registerTimeout,
		Transport: &http.Transport{
			TLSClientConfig:     tlsCfg,
			TLSHandshakeTimeout: 10 * time.Second,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errRegistrationRedirect
		},
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	var serverIP string
	trace := &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
		host, _, splitErr := net.SplitHostPort(info.Conn.RemoteAddr().String())
		if splitErr == nil {
			serverIP = host
		}
	}}
	httpReq = httpReq.WithContext(httptrace.WithClientTrace(httpReq.Context(), trace))
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	resp, err := hc.Do(httpReq)
	if err != nil {
		if errors.Is(err, errRegistrationRedirect) {
			return nil, errRegistrationRedirect
		}
		return nil, fmt.Errorf("register request: %w", err)
	}
	defer resp.Body.Close()
	respBody, err := readLimitedBody(resp.Body, maxRegisterResponseBytes)
	if err != nil {
		return nil, fmt.Errorf("read register response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		// Never echo the response body: a failing peer may reflect the token.
		return nil, fmt.Errorf("register failed (%d)", resp.StatusCode)
	}

	var reg protocol.RegisterResponse
	if err := json.Unmarshal(respBody, &reg); err != nil {
		return nil, errors.New("invalid registration response")
	}
	if err := validateRegistrationResponse(&reg, csr, localPub, agentID); err != nil {
		return nil, err
	}
	if serverIP == "" {
		return nil, errors.New("registration succeeded but Server peer IP was unavailable")
	}
	return &Registration{
		AgentID:     reg.AgentID,
		CertPEM:     []byte(reg.CertPEM),
		CAPEM:       []byte(reg.CAPEM),
		ServerCAPEM: []byte(reg.ServerCAPEM),
		ServerIP:    serverIP,
	}, nil
}

// registrationEndpoint validates serverURL and returns the fixed registration
// endpoint. Only HTTPS is accepted; userinfo, queries, fragments and malformed
// hosts are rejected so the token cannot be steered to another origin.
func registrationEndpoint(serverURL string) (string, error) {
	raw := strings.TrimSpace(serverURL)
	if raw == "" {
		return "", errors.New("server URL is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid server URL: %w", err)
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return "", fmt.Errorf("server URL must use https, got %q", u.Scheme)
	}
	if u.Opaque != "" || u.Host == "" || u.Hostname() == "" {
		return "", errors.New("server URL must include a host")
	}
	if u.User != nil {
		return "", errors.New("server URL must not contain userinfo")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("server URL must not contain a query or fragment")
	}
	u.Path = path.Join(u.Path, protocol.ControlAPIPrefix, "register")
	u.RawPath = ""
	return u.String(), nil
}

// parsePinnedFingerprint accepts the SHA-256 digest of a TLS leaf certificate
// in exactly two shapes: 64 hex characters, or 32 colon-separated two-hex-byte
// groups. Both may carry a case-insensitive "SHA256:" prefix and surrounding
// whitespace (the historical normalizeFingerprint trimmed it). Only the
// literal empty string means "no pin"; a value that is empty after trimming or
// otherwise malformed is rejected rather than silently falling back to
// public-PKI verification.
func parsePinnedFingerprint(fp string) ([]byte, error) {
	if fp == "" {
		return nil, nil
	}
	s := strings.TrimSpace(fp)
	if s == "" {
		return nil, errors.New("invalid fingerprint: whitespace only")
	}
	const prefix = "SHA256:"
	if len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix) {
		s = s[len(prefix):]
	}
	var hexDigest string
	switch {
	case len(s) == sha256.Size*2 && !strings.Contains(s, ":"):
		hexDigest = s
	case strings.Count(s, ":") == sha256.Size-1:
		groups := strings.Split(s, ":")
		for _, group := range groups {
			if len(group) != 2 {
				return nil, errors.New("invalid fingerprint: colon-separated form needs 32 two-hex groups")
			}
		}
		hexDigest = strings.Join(groups, "")
	default:
		return nil, errors.New("invalid fingerprint: want 64 hex characters or 32 colon-separated groups")
	}
	sum, err := hex.DecodeString(hexDigest)
	if err != nil {
		return nil, fmt.Errorf("invalid fingerprint: %w", err)
	}
	return sum, nil
}

// validateRegistrationResponse checks the server's answer before any identity
// material is written: agent ID, certificate/key/CSR agreement, CA issuance,
// serverAuth usage, validity and expiry metadata.
func validateRegistrationResponse(reg *protocol.RegisterResponse, csr *x509.CertificateRequest, localPub any, requestedAgentID string) error {
	if reg == nil {
		return errors.New("empty registration response")
	}
	if err := validateAgentID(reg.AgentID); err != nil {
		return err
	}
	if requestedAgentID != "" && reg.AgentID != requestedAgentID {
		return fmt.Errorf("server returned agent id %q, want %q", reg.AgentID, requestedAgentID)
	}
	leaf, err := parseSingleCertificatePEM([]byte(reg.CertPEM))
	if err != nil {
		return fmt.Errorf("invalid agent certificate: %w", err)
	}
	issuingCA, err := parseSingleCertificatePEM([]byte(reg.CAPEM))
	if err != nil {
		return fmt.Errorf("invalid issuing CA: %w", err)
	}
	serverCA, err := parseSingleCertificatePEM([]byte(reg.ServerCAPEM))
	if err != nil {
		return fmt.Errorf("invalid server CA: %w", err)
	}
	if !issuingCA.IsCA {
		return errors.New("issuing CA certificate is not a CA")
	}
	if !serverCA.IsCA {
		return errors.New("server CA certificate is not a CA")
	}
	if leaf.IsCA {
		return errors.New("agent certificate must not be a CA")
	}
	if !publicKeysEqual(leaf.PublicKey, csr.PublicKey) {
		return errors.New("agent certificate does not match the CSR public key")
	}
	if localPub != nil && !publicKeysEqual(leaf.PublicKey, localPub) {
		return errors.New("agent certificate does not match the local private key")
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) {
		return fmt.Errorf("agent certificate is not valid before %s", leaf.NotBefore.Format(time.RFC3339))
	}
	if !now.Before(leaf.NotAfter) {
		return fmt.Errorf("agent certificate expired at %s", leaf.NotAfter.Format(time.RFC3339))
	}
	if !hasExtKeyUsage(leaf, x509.ExtKeyUsageServerAuth) {
		return errors.New("agent certificate is not valid for server authentication")
	}
	roots := x509.NewCertPool()
	roots.AddCert(issuingCA)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return fmt.Errorf("agent certificate is not signed by the returned CA: %w", err)
	}
	// This deployment uses one internal CA for both the agent identity and the
	// server's client identity. Require the returned server trust anchor to
	// actually be that CA, so a mismatched ServerCAPEM cannot be persisted.
	serverRoots := x509.NewCertPool()
	serverRoots.AddCert(serverCA)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:       serverRoots,
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return fmt.Errorf("server CA does not match the agent certificate issuer: %w", err)
	}
	if reg.ExpiresAt != "" {
		expiresAt, err := time.Parse(time.RFC3339, reg.ExpiresAt)
		if err != nil {
			return fmt.Errorf("invalid expires_at: %w", err)
		}
		if expiresAt.Unix() != leaf.NotAfter.Unix() {
			return errors.New("expires_at does not match the certificate")
		}
	}
	return nil
}

func validateAgentID(id string) error {
	if id == "" {
		return errors.New("registration response is missing agent id")
	}
	if len(id) > 256 {
		return errors.New("registration response agent id is too long")
	}
	for _, r := range id {
		if r < 0x20 || r == 0x7f {
			return errors.New("registration response agent id contains control characters")
		}
	}
	return nil
}

// decodeStrictPEM decodes exactly one PEM block of wantType. Unlike
// pem.Decode it never skips leading garbage or a malformed first block: only
// leading whitespace is allowed, the first BEGIN line must carry the expected
// type, PEM headers are rejected, and anything but whitespace after the END
// line is an error.
func decodeStrictPEM(data []byte, wantType string) (*pem.Block, error) {
	block, err := decodeStrictPEMAny(data)
	if err != nil {
		return nil, err
	}
	if block.Type != wantType {
		return nil, fmt.Errorf("unexpected PEM block %q, want %q", block.Type, wantType)
	}
	return block, nil
}

func decodeStrictPEMAny(data []byte) (*pem.Block, error) {
	pos := 0
	for pos < len(data) && isPEMWhitespace(data[pos]) {
		pos++
	}
	const beginPrefix = "-----BEGIN "
	if !bytes.HasPrefix(data[pos:], []byte(beginPrefix)) {
		return nil, errors.New("PEM data does not start with a BEGIN block")
	}
	beginLineEnd := bytes.IndexByte(data[pos:], '\n')
	if beginLineEnd < 0 {
		return nil, errors.New("unterminated PEM BEGIN line")
	}
	beginLine := bytes.TrimSuffix(data[pos:pos+beginLineEnd], []byte("\r"))
	if !bytes.HasSuffix(beginLine, []byte("-----")) {
		return nil, errors.New("malformed PEM BEGIN line")
	}
	blockType := string(beginLine[len(beginPrefix) : len(beginLine)-5])
	bodyStart := pos + beginLineEnd + 1
	endMarker := []byte("-----END " + blockType + "-----")
	endAt := -1
	for search := bodyStart; search < len(data); {
		idx := bytes.Index(data[search:], endMarker)
		if idx < 0 {
			break
		}
		at := search + idx
		if at == bodyStart || data[at-1] == '\n' {
			endAt = at
			break
		}
		search = at + len(endMarker)
	}
	if endAt < 0 {
		return nil, fmt.Errorf("missing PEM END for %q", blockType)
	}
	afterEnd := endAt + len(endMarker)
	for afterEnd < len(data) && (data[afterEnd] == ' ' || data[afterEnd] == '\t') {
		afterEnd++
	}
	if afterEnd < len(data) {
		switch data[afterEnd] {
		case '\r':
			afterEnd++
			if afterEnd >= len(data) || data[afterEnd] != '\n' {
				return nil, errors.New("malformed PEM END line")
			}
			afterEnd++
		case '\n':
			afterEnd++
		default:
			return nil, errors.New("malformed PEM END line")
		}
	}
	if len(bytes.TrimSpace(data[afterEnd:])) != 0 {
		return nil, errors.New("unexpected trailing data after PEM block")
	}
	var base64Body []byte
	for _, c := range data[bodyStart:endAt] {
		switch c {
		case ' ', '\t', '\r', '\n':
			continue
		case ':':
			return nil, fmt.Errorf("PEM %q block must not contain headers", blockType)
		default:
			base64Body = append(base64Body, c)
		}
	}
	der, err := base64.StdEncoding.DecodeString(string(base64Body))
	if err != nil {
		return nil, fmt.Errorf("invalid PEM %q body: %w", blockType, err)
	}
	return &pem.Block{Type: blockType, Bytes: der}, nil
}

func isPEMWhitespace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\r' || b == '\n'
}

func parseCSR(csrPEM []byte) (*x509.CertificateRequest, error) {
	block, err := decodeStrictPEM(csrPEM, "CERTIFICATE REQUEST")
	if err != nil {
		return nil, fmt.Errorf("CSR is not a valid PEM certificate request: %w", err)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature invalid: %w", err)
	}
	return csr, nil
}

func parseSingleCertificatePEM(certPEM []byte) (*x509.Certificate, error) {
	block, err := decodeStrictPEM(certPEM, "CERTIFICATE")
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(block.Bytes)
}

func publicKeyFromPrivateKeyPEM(keyPEM []byte) (any, error) {
	block, err := decodeStrictPEMAny(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("private key is not valid PEM: %w", err)
	}
	switch block.Type {
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse EC private key: %w", err)
		}
		return key.Public(), nil
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse RSA private key: %w", err)
		}
		return key.Public(), nil
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKCS#8 private key: %w", err)
		}
		if signer, ok := key.(interface{ Public() any }); ok {
			return signer.Public(), nil
		}
		return nil, errors.New("unsupported PKCS#8 private key")
	default:
		return nil, fmt.Errorf("unsupported private key type %q", block.Type)
	}
}

func publicKeysEqual(a, b any) bool {
	if a == nil || b == nil {
		return false
	}
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

func hasExtKeyUsage(cert *x509.Certificate, want x509.ExtKeyUsage) bool {
	for _, usage := range cert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageAny || usage == want {
			return true
		}
	}
	return false
}

func certSHA256(cert *x509.Certificate) []byte {
	sum := sha256.Sum256(cert.Raw)
	return sum[:]
}

func readLimitedBody(r io.Reader, limit int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("response exceeds %d bytes", limit)
	}
	return body, nil
}
