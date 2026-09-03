package agent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/Flyinsky2004/oh-my-acme/internal/protocol"
)

func TestVerifyCertMaterial(t *testing.T) {
	key := mustKey(t)
	certPEM, privPEM := mustCert(t, key, "example.com", "*.example.com", time.Now(), time.Now().Add(time.Hour))

	ok := protocol.DeployRequest{
		RootDomain:    "example.com",
		CertPEM:       certPEM,
		PrivateKeyPEM: privPEM,
	}
	if err := verifyCertMaterial(ok); err != nil {
		t.Fatalf("should pass: %v", err)
	}

	// Wrong root domain.
	if err := verifyCertMaterial(protocol.DeployRequest{RootDomain: "other.com", CertPEM: certPEM, PrivateKeyPEM: privPEM}); err == nil {
		t.Fatal("expected error for wrong domain")
	}

	// Expired.
	_ = key
	expKey := mustKey(t)
	expCert, expPriv := mustCert(t, expKey, "example.com", "*.example.com", time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour))
	if err := verifyCertMaterial(protocol.DeployRequest{RootDomain: "example.com", CertPEM: expCert, PrivateKeyPEM: expPriv}); err == nil {
		t.Fatal("expected error for expired cert")
	}

	// Mismatched key.
	otherKey := mustKey(t)
	_, otherPriv := mustCert(t, otherKey, "example.com", "*.example.com", time.Now(), time.Now().Add(time.Hour))
	if err := verifyCertMaterial(protocol.DeployRequest{RootDomain: "example.com", CertPEM: certPEM, PrivateKeyPEM: otherPriv}); err == nil {
		t.Fatal("expected error for mismatched key")
	}
}

func mustKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func mustCert(t *testing.T, key *ecdsa.PrivateKey, cn string, wildcard string, nb, na time.Time) (string, string) {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    nb,
		NotAfter:     na,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		DNSNames:     []string{cn, wildcard},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
}
