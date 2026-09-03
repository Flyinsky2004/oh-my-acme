package pki

import (
	"crypto/x509"
	"encoding/pem"
	"net"
	"testing"
)

func TestNewCAFingerprint(t *testing.T) {
	ca, err := NewCA("test-ca")
	if err != nil {
		t.Fatal(err)
	}
	fp := ca.Fingerprint()
	if fp == "" || fp[:7] != "SHA256:" {
		t.Fatalf("bad fingerprint %q", fp)
	}
	// Round-trip parse.
	cert2, err := ParseCACert(ca.EncodeCA())
	if err != nil {
		t.Fatal(err)
	}
	if cert2.Subject.CommonName != "test-ca" {
		t.Fatalf("unexpected CN %q", cert2.Subject.CommonName)
	}
}

func TestSignServerIdentity(t *testing.T) {
	ca, err := NewCA("test-ca")
	if err != nil {
		t.Fatal(err)
	}
	kp, err := ca.SignServerIdentity([]net.IP{net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	leaf, err := x509.ParseCertificate(pemBlock(kp.CertPEM, "CERTIFICATE"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "localhost"}); err != nil {
		t.Fatalf("verify localhost: %v", err)
	}
}

func TestSignAgentCSR(t *testing.T) {
	ca, err := NewCA("test-ca")
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, csrPEM, err := generateTestCSR("oh-my-acme-agent:test")
	if err != nil {
		t.Fatal(err)
	}
	_ = keyPEM
	kp, err := ca.SignAgentCSR(csrPEM, []net.IP{net.ParseIP("203.0.113.7")})
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	leaf, err := x509.ParseCertificate(pemBlock(kp.CertPEM, "CERTIFICATE"))
	if err != nil {
		t.Fatal(err)
	}
	opts := x509.VerifyOptions{Roots: pool}
	if _, err := leaf.Verify(opts); err != nil {
		t.Fatalf("verify agent cert: %v", err)
	}
	if len(leaf.IPAddresses) != 1 || leaf.IPAddresses[0].String() != "203.0.113.7" {
		t.Fatalf("expected IP SAN 203.0.113.7, got %v", leaf.IPAddresses)
	}
}

func pemBlock(b []byte, typ string) []byte {
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != typ {
		return nil
	}
	return blk.Bytes
}
