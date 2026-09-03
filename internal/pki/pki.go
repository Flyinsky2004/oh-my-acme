// Package pki implements a lightweight internal private PKI used for mTLS
// between the oh-my-acme server and its agents. It does not depend on any
// third-party public CA. The CA is a single self-signed root; the server holds
// one TLS-server identity (for the control port) and one client identity (for
// pushing to agents); each agent receives a server identity issued from a CSR
// it submitted, containing its source IP as an IP SAN.
package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"time"
)

const (
	// CAPeriod is how long the self-signed CA and the non-rotating identity
	// certificates are valid. The user explicitly chose no automatic rotation,
	// so identity certs are long-lived.
	CAPeriod   = 10 * 365 * 24 * time.Hour
	CertPeriod = 10 * 365 * 24 * time.Hour
)

// CA holds the private CA certificate and key. It may be used to sign
// identities for the server and the agents.
type CA struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
}

// KeyPair is a parsed certificate + private key ready for use with TLS.
type KeyPair struct {
	CertPEM []byte
	KeyPEM  []byte
	Cert    *x509.Certificate
	Key     *ecdsa.PrivateKey
}

// Fingerprint returns the hex-encoded SHA-256 fingerprint of the CA certificate.
func (ca *CA) Fingerprint() string {
	h := sha256.Sum256(ca.Cert.Raw)
	return "SHA256:" + hex.EncodeToString(h[:])
}

// Fingerprint returns the SHA-256 fingerprint of the certificate, formatted
// as SHA256:<hex>. For an identity KeyPair this is the leaf certificate's own
// fingerprint — the value an agent pins when it connects to the server.
func (kp *KeyPair) Fingerprint() string {
	if kp.Cert == nil {
		return ""
	}
	h := sha256.Sum256(kp.Cert.Raw)
	return "SHA256:" + hex.EncodeToString(h[:])
}

// newSerial produces a random positive serial number.
func newSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, err
	}
	return n, nil
}

// NewCA generates a new self-signed CA for the project. The key is generated
// on the current machine; the caller must persist it under root-owned 0700 /
// 0600 paths.
func NewCA(commonName string) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"oh-my-acme"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(CAPeriod),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, Key: key}, nil
}

// sign issues a child certificate signed by the CA using the given template
// and public key.
func (ca *CA) sign(tmpl *x509.Certificate, pub any) (*x509.Certificate, error) {
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, pub, ca.Key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// newIdentityTemplate builds a template for a server or client identity.
// dnsNames / ips are copied into SANs; extKeyUsage determines the purpose.
func newIdentityTemplate(cn string, dnsNames []string, ips []net.IP, extKeyUsage []x509.ExtKeyUsage) (*x509.Certificate, error) {
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	return &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"oh-my-acme"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(CertPeriod),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           extKeyUsage,
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              dnsNames,
		IPAddresses:           ips,
	}, nil
}

// SignServerIdentity issues the server's TLS identity used on the control
// port, including localhost and the given server IP(s) as SANs.
func (ca *CA) SignServerIdentity(serverIPs []net.IP) (*KeyPair, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	dns := []string{"localhost"}
	tmpl, err := newIdentityTemplate("oh-my-acme-server", dns, serverIPs, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	if err != nil {
		return nil, err
	}
	cert, err := ca.sign(tmpl, &key.PublicKey)
	if err != nil {
		return nil, err
	}
	return marshalPair(cert, key)
}

// SignServerClientIdentity issues the client certificate the server presents
// when it connects (via mTLS) to agents. Purpose is ClientAuth.
func (ca *CA) SignServerClientIdentity() (*KeyPair, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl, err := newIdentityTemplate("oh-my-acme-server-push", nil, nil, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	if err != nil {
		return nil, err
	}
	cert, err := ca.sign(tmpl, &key.PublicKey)
	if err != nil {
		return nil, err
	}
	return marshalPair(cert, key)
}

// SignAgentCSR issues an agent server identity from a PEM CSR supplied by the
// agent, embedding the given source IP(s). The agent keeps its private key.
func (ca *CA) SignAgentCSR(csrPEM []byte, ips []net.IP) (*KeyPair, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("invalid CSR: not PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("invalid CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature invalid: %w", err)
	}
	tmpl, err := newIdentityTemplate(csr.Subject.CommonName, csr.DNSNames, ips, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	if err != nil {
		return nil, err
	}
	cert, err := ca.sign(tmpl, csr.PublicKey)
	if err != nil {
		return nil, err
	}
	// marshal the certificate only (no key) into a KeyPair for transport.
	var certPEMBuf []byte
	if err := encodeCert(cert, &certPEMBuf); err != nil {
		return nil, err
	}
	return &KeyPair{CertPEM: certPEMBuf, Cert: cert}, nil
}

func marshalPair(cert *x509.Certificate, key *ecdsa.PrivateKey) (*KeyPair, error) {
	var certPEM, keyPEM []byte
	if err := encodeCert(cert, &certPEM); err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return &KeyPair{CertPEM: certPEM, KeyPEM: keyPEM, Cert: cert, Key: key}, nil
}

func encodeCert(cert *x509.Certificate, out *[]byte) error {
	*out = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	return nil
}

// --- Loading / wrapping for TLS use ---

// TLSCertificate builds a tls.Certificate from a KeyPair (used when the key is
// present, e.g. the server's own identity). Returns CN as an extra.
func (kp *KeyPair) TLSCertificate() (tls.Certificate, error) {
	if len(kp.KeyPEM) == 0 {
		return tls.Certificate{}, errors.New("KeyPair has no private key")
	}
	cert, err := tls.X509KeyPair(kp.CertPEM, kp.KeyPEM)
	if err != nil {
		return tls.Certificate{}, err
	}
	return cert, nil
}

// EncodeCA returns the CA certificate as PEM.
func (ca *CA) EncodeCA() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert.Raw})
}

// EncodeKey returns the CA private key as PEM.
func (ca *CA) EncodeKey() []byte {
	der, _ := x509.MarshalECPrivateKey(ca.Key)
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

// ParseCACert parses a CA PEM certificate.
func ParseCACert(pemBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("invalid CA PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}

// ParseCAKey parses an EC CA private key PEM.
func ParseCAKey(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		return nil, errors.New("invalid CA key PEM")
	}
	return x509.ParseECPrivateKey(block.Bytes)
}

// ParseCertificatePEM parses a single PEM certificate.
func ParseCertificatePEM(pemBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("invalid certificate PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}
