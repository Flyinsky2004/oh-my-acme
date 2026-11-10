package agent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/Flyinsky2004/oh-my-acme/internal/protocol"
)

// testCA is a generated CA certificate and key used to build real chains.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  string
}

// testChain is a leaf plus its issuer chain. fullchainPEM is leaf+inter+root,
// caPEM is inter+root, matching what the server pushes.
type testChain struct {
	root         *testCA
	intermediate *testCA
	leaf         *x509.Certificate
	leafKey      *ecdsa.PrivateKey
	certPEM      string
	keyPEM       string
	fullchainPEM string
	caPEM        string
}

type leafSpec struct {
	nb              time.Time
	na              time.Time
	dns             []string
	eku             []x509.ExtKeyUsage
	keyUsage        x509.KeyUsage
	isCA            bool
	extraExtensions []pkix.Extension
}

func newTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func pemCert(cert *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
}

func pemECKey(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
}

func newTestSerial(t *testing.T) *big.Int {
	t.Helper()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		t.Fatal(err)
	}
	return serial
}

// caSpec controls optional CA constraints used by the verification tests.
type caSpec struct {
	maxPathLen           int
	maxPathLenZero       bool
	eku                  []x509.ExtKeyUsage
	permittedDNS         []string
	permittedDNSCritical bool
}

// newTestCA issues a CA certificate. parent == nil makes a self-signed root.
func newTestCA(t *testing.T, cn string, parent *testCA, maxPathLen int, maxPathLenZero bool) *testCA {
	t.Helper()
	return newTestCAWithSpec(t, cn, parent, caSpec{maxPathLen: maxPathLen, maxPathLenZero: maxPathLenZero})
}

func newTestCAWithSpec(t *testing.T, cn string, parent *testCA, spec caSpec) *testCA {
	t.Helper()
	key := newTestKey(t)
	tmpl := &x509.Certificate{
		SerialNumber:                newTestSerial(t),
		Subject:                     pkix.Name{CommonName: cn},
		NotBefore:                   time.Now().Add(-time.Hour),
		NotAfter:                    time.Now().Add(24 * time.Hour),
		KeyUsage:                    x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:                 spec.eku,
		BasicConstraintsValid:       true,
		IsCA:                        true,
		MaxPathLen:                  spec.maxPathLen,
		MaxPathLenZero:              spec.maxPathLenZero,
		PermittedDNSDomains:         spec.permittedDNS,
		PermittedDNSDomainsCritical: spec.permittedDNSCritical,
	}
	parentCert, parentKey := tmpl, key
	if parent != nil {
		parentCert, parentKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parentCert, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{cert: cert, key: key, pem: pemCert(cert)}
}

// newTestLeaf issues a leaf (or a self-signed leaf when parent == nil).
func newTestLeaf(t *testing.T, parent *testCA, spec leafSpec) (cert *x509.Certificate, key *ecdsa.PrivateKey, certPEM, keyPEM string) {
	t.Helper()
	key = newTestKey(t)
	if spec.nb.IsZero() {
		spec.nb = time.Now().Add(-time.Hour)
	}
	if spec.na.IsZero() {
		spec.na = time.Now().Add(24 * time.Hour)
	}
	if len(spec.dns) == 0 {
		spec.dns = []string{"example.com", "*.example.com"}
	}
	if spec.keyUsage == 0 {
		spec.keyUsage = x509.KeyUsageDigitalSignature
	}
	tmpl := &x509.Certificate{
		SerialNumber:          newTestSerial(t),
		Subject:               pkix.Name{CommonName: spec.dns[0]},
		NotBefore:             spec.nb,
		NotAfter:              spec.na,
		KeyUsage:              spec.keyUsage,
		ExtKeyUsage:           spec.eku,
		DNSNames:              spec.dns,
		BasicConstraintsValid: true,
		IsCA:                  spec.isCA,
		ExtraExtensions:       spec.extraExtensions,
	}
	parentCert, parentKey := tmpl, key
	if parent != nil {
		parentCert, parentKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parentCert, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key, pemCert(cert), pemECKey(t, key)
}

func newTestChain(t *testing.T, spec leafSpec) *testChain {
	t.Helper()
	root := newTestCA(t, "Test Root", nil, 0, false)
	inter := newTestCA(t, "Test Intermediate", root, 0, false)
	leaf, key, certPEM, keyPEM := newTestLeaf(t, inter, spec)
	return &testChain{
		root:         root,
		intermediate: inter,
		leaf:         leaf,
		leafKey:      key,
		certPEM:      certPEM,
		keyPEM:       keyPEM,
		fullchainPEM: certPEM + inter.pem + root.pem,
		caPEM:        inter.pem + root.pem,
	}
}

func newSelfSignedChain(t *testing.T, spec leafSpec) *testChain {
	t.Helper()
	leaf, key, certPEM, keyPEM := newTestLeaf(t, nil, spec)
	return &testChain{
		leaf: leaf, leafKey: key,
		certPEM: certPEM, keyPEM: keyPEM,
		fullchainPEM: certPEM, caPEM: certPEM,
	}
}

func (c *testChain) request(root string) protocol.DeployRequest {
	return protocol.DeployRequest{
		RootDomain:    root,
		CertPEM:       c.certPEM,
		CAPEM:         c.caPEM,
		FullchainPEM:  c.fullchainPEM,
		PrivateKeyPEM: c.keyPEM,
	}
}

func TestVerifyCertMaterialAcceptsValidChain(t *testing.T) {
	chain := newTestChain(t, leafSpec{})
	if err := verifyCertMaterial(chain.request("example.com")); err != nil {
		t.Fatalf("valid chain rejected: %v", err)
	}

	// Root omitted: the intermediate is the trust anchor.
	truncated := chain.request("example.com")
	truncated.FullchainPEM = chain.certPEM + chain.intermediate.pem
	truncated.CAPEM = chain.intermediate.pem
	if err := verifyCertMaterial(truncated); err != nil {
		t.Fatalf("truncated chain rejected: %v", err)
	}

	// Empty ca.pem is compatible when fullchain carries the issuers.
	noCA := chain.request("example.com")
	noCA.CAPEM = ""
	if err := verifyCertMaterial(noCA); err != nil {
		t.Fatalf("empty ca.pem rejected: %v", err)
	}

	// Self-signed leaf as the whole chain (private self-signed deployment).
	self := newSelfSignedChain(t, leafSpec{})
	if err := verifyCertMaterial(self.request("example.com")); err != nil {
		t.Fatalf("self-signed leaf rejected: %v", err)
	}
}

func TestVerifyCertMaterialAcceptsPKCS8Key(t *testing.T) {
	chain := newTestChain(t, leafSpec{})
	der, err := x509.MarshalPKCS8PrivateKey(chain.leafKey)
	if err != nil {
		t.Fatal(err)
	}
	req := chain.request("example.com")
	req.PrivateKeyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	if err := verifyCertMaterial(req); err != nil {
		t.Fatalf("PKCS#8 key rejected: %v", err)
	}
}

func TestVerifyCertMaterialRejectsBadMaterial(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name    string
		build   func(t *testing.T) protocol.DeployRequest
		wantSub string
	}{
		{
			name: "wrong root domain",
			build: func(t *testing.T) protocol.DeployRequest {
				return newTestChain(t, leafSpec{}).request("other.com")
			},
			wantSub: "does not cover",
		},
		{
			name: "expired leaf",
			build: func(t *testing.T) protocol.DeployRequest {
				return newTestChain(t, leafSpec{nb: now.Add(-2 * time.Hour), na: now.Add(-time.Hour)}).request("example.com")
			},
			wantSub: "expired",
		},
		{
			name: "not yet valid leaf",
			build: func(t *testing.T) protocol.DeployRequest {
				return newTestChain(t, leafSpec{nb: now.Add(time.Hour), na: now.Add(2 * time.Hour)}).request("example.com")
			},
			wantSub: "not yet valid",
		},
		{
			name: "missing wildcard SAN",
			build: func(t *testing.T) protocol.DeployRequest {
				return newTestChain(t, leafSpec{dns: []string{"example.com"}}).request("example.com")
			},
			wantSub: "does not cover *.",
		},
		{
			name: "wrong private key",
			build: func(t *testing.T) protocol.DeployRequest {
				chain := newTestChain(t, leafSpec{})
				other := newTestChain(t, leafSpec{})
				req := chain.request("example.com")
				req.PrivateKeyPEM = other.keyPEM
				return req
			},
			wantSub: "does not match",
		},
		{
			name: "cert.pem does not match fullchain leaf",
			build: func(t *testing.T) protocol.DeployRequest {
				chain := newTestChain(t, leafSpec{})
				other := newTestChain(t, leafSpec{})
				req := chain.request("example.com")
				req.CertPEM = other.certPEM
				return req
			},
			wantSub: "does not match the first certificate",
		},
		{
			name: "fullchain missing issuer",
			build: func(t *testing.T) protocol.DeployRequest {
				chain := newTestChain(t, leafSpec{})
				req := chain.request("example.com")
				req.FullchainPEM = chain.certPEM
				return req
			},
			wantSub: "not self-signed",
		},
		{
			name: "fullchain wrong order",
			build: func(t *testing.T) protocol.DeployRequest {
				chain := newTestChain(t, leafSpec{})
				req := chain.request("example.com")
				req.FullchainPEM = chain.intermediate.pem + chain.certPEM + chain.root.pem
				return req
			},
			wantSub: "does not match the first certificate",
		},
		{
			name: "fullchain contains a non-certificate block",
			build: func(t *testing.T) protocol.DeployRequest {
				chain := newTestChain(t, leafSpec{})
				req := chain.request("example.com")
				req.FullchainPEM = chain.certPEM + chain.keyPEM
				return req
			},
			wantSub: "unexpected PEM block",
		},
		{
			name: "fullchain trailing garbage",
			build: func(t *testing.T) protocol.DeployRequest {
				chain := newTestChain(t, leafSpec{})
				req := chain.request("example.com")
				req.FullchainPEM += "\ngarbage\n"
				return req
			},
			wantSub: "trailing non-PEM data",
		},
		{
			name: "malformed first block followed by valid chain",
			build: func(t *testing.T) protocol.DeployRequest {
				chain := newTestChain(t, leafSpec{})
				req := chain.request("example.com")
				req.FullchainPEM = "-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n" + chain.fullchainPEM
				return req
			},
			wantSub: "invalid PEM block",
		},
		{
			name: "nested PEM BEGIN before END",
			build: func(t *testing.T) protocol.DeployRequest {
				chain := newTestChain(t, leafSpec{})
				req := chain.request("example.com")
				req.FullchainPEM = "-----BEGIN CERTIFICATE-----\n" + chain.certPEM + "-----END CERTIFICATE-----\n"
				return req
			},
			wantSub: "nested PEM BEGIN",
		},
		{
			name: "malformed first private key block",
			build: func(t *testing.T) protocol.DeployRequest {
				chain := newTestChain(t, leafSpec{})
				req := chain.request("example.com")
				req.PrivateKeyPEM = "-----BEGIN EC PRIVATE KEY-----\n!!!!\n-----END EC PRIVATE KEY-----\n" + chain.keyPEM
				return req
			},
			wantSub: "invalid PEM block",
		},
		{
			name: "ca.pem mismatch",
			build: func(t *testing.T) protocol.DeployRequest {
				chain := newTestChain(t, leafSpec{})
				req := chain.request("example.com")
				req.CAPEM = chain.root.pem
				return req
			},
			wantSub: "ca.pem",
		},
		{
			name: "ca.pem invalid non-empty",
			build: func(t *testing.T) protocol.DeployRequest {
				chain := newTestChain(t, leafSpec{})
				req := chain.request("example.com")
				req.CAPEM = "not a pem"
				return req
			},
			wantSub: "ca.pem",
		},
		{
			name: "leaf is a CA",
			build: func(t *testing.T) protocol.DeployRequest {
				return newTestChain(t, leafSpec{
					isCA:     true,
					keyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
				}).request("example.com")
			},
			wantSub: "CA certificate",
		},
		{
			name: "leaf EKU is client auth only",
			build: func(t *testing.T) protocol.DeployRequest {
				return newTestChain(t, leafSpec{eku: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}).request("example.com")
			},
			wantSub: "TLS server authentication",
		},
		{
			name: "leaf key usage cannot sign",
			build: func(t *testing.T) protocol.DeployRequest {
				return newTestChain(t, leafSpec{keyUsage: x509.KeyUsageCertSign}).request("example.com")
			},
			wantSub: "digital signatures",
		},
		{
			name: "corrupted leaf signature",
			build: func(t *testing.T) protocol.DeployRequest {
				chain := newTestChain(t, leafSpec{})
				req := chain.request("example.com")
				req.CertPEM = corruptPEMSignature(t, chain.certPEM)
				req.FullchainPEM = req.CertPEM + chain.intermediate.pem + chain.root.pem
				return req
			},
			wantSub: "signature",
		},
		{
			name: "chain signed by a different CA",
			build: func(t *testing.T) protocol.DeployRequest {
				chainA := newTestChain(t, leafSpec{})
				chainB := newTestChain(t, leafSpec{})
				req := chainA.request("example.com")
				req.FullchainPEM = chainA.certPEM + chainB.intermediate.pem + chainB.root.pem
				req.CAPEM = chainB.intermediate.pem + chainB.root.pem
				return req
			},
			wantSub: "signature",
		},
		{
			name: "unknown critical extension",
			build: func(t *testing.T) protocol.DeployRequest {
				oid := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}
				return newTestChain(t, leafSpec{extraExtensions: []pkix.Extension{{
					Id: oid, Critical: true, Value: []byte{0x05, 0x00},
				}}}).request("example.com")
			},
			wantSub: "unhandled critical extension",
		},
		{
			name: "path length constraint",
			build: func(t *testing.T) protocol.DeployRequest {
				root := newTestCA(t, "Path Root", nil, 0, false)
				// inter1 permits zero intermediates below it.
				inter1 := newTestCA(t, "Path Intermediate 1", root, 0, true)
				inter2 := newTestCA(t, "Path Intermediate 2", inter1, 0, false)
				_, _, certPEM, keyPEM := newTestLeaf(t, inter2, leafSpec{})
				return protocol.DeployRequest{
					RootDomain:    "example.com",
					CertPEM:       certPEM,
					CAPEM:         inter2.pem + inter1.pem + root.pem,
					FullchainPEM:  certPEM + inter2.pem + inter1.pem + root.pem,
					PrivateKeyPEM: keyPEM,
				}
			},
			wantSub: "too many intermediates",
		},
		{
			name: "name constraints",
			build: func(t *testing.T) protocol.DeployRequest {
				root := newTestCAWithSpec(t, "NC Root", nil, caSpec{
					permittedDNS:         []string{"example.org"},
					permittedDNSCritical: true,
				})
				inter := newTestCA(t, "NC Intermediate", root, 0, false)
				_, _, certPEM, keyPEM := newTestLeaf(t, inter, leafSpec{})
				return protocol.DeployRequest{
					RootDomain:    "example.com",
					CertPEM:       certPEM,
					CAPEM:         inter.pem + root.pem,
					FullchainPEM:  certPEM + inter.pem + root.pem,
					PrivateKeyPEM: keyPEM,
				}
			},
			wantSub: "certificate chain verification",
		},
		{
			name: "intermediate CA EKU does not permit server auth",
			build: func(t *testing.T) protocol.DeployRequest {
				root := newTestCA(t, "EKU Root", nil, 0, false)
				inter := newTestCAWithSpec(t, "EKU Intermediate", root, caSpec{
					eku: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
				})
				_, _, certPEM, keyPEM := newTestLeaf(t, inter, leafSpec{
					eku: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
				})
				return protocol.DeployRequest{
					RootDomain:    "example.com",
					CertPEM:       certPEM,
					CAPEM:         inter.pem + root.pem,
					FullchainPEM:  certPEM + inter.pem + root.pem,
					PrivateKeyPEM: keyPEM,
				}
			},
			wantSub: "certificate chain verification",
		},
		{
			name: "self-signed leaf unknown critical extension",
			build: func(t *testing.T) protocol.DeployRequest {
				oid := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 2}
				return newSelfSignedChain(t, leafSpec{extraExtensions: []pkix.Extension{{
					Id: oid, Critical: true, Value: []byte{0x05, 0x00},
				}}}).request("example.com")
			},
			wantSub: "unhandled critical extension",
		},
		{
			name: "empty fullchain",
			build: func(t *testing.T) protocol.DeployRequest {
				chain := newTestChain(t, leafSpec{})
				req := chain.request("example.com")
				req.FullchainPEM = ""
				return req
			},
			wantSub: "no certificates",
		},
		{
			name: "empty cert.pem",
			build: func(t *testing.T) protocol.DeployRequest {
				chain := newTestChain(t, leafSpec{})
				req := chain.request("example.com")
				req.CertPEM = ""
				return req
			},
			wantSub: "expected exactly one certificate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifyCertMaterial(tt.build(t))
			if err == nil {
				t.Fatal("expected verification error")
			}
			if !strings.Contains(err.Error(), tt.wantSub) {
				t.Fatalf("error %q does not contain %q", err, tt.wantSub)
			}
		})
	}
}

func corruptPEMSignature(t *testing.T, certPEM string) string {
	t.Helper()
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		t.Fatal("invalid certificate PEM")
	}
	der := append([]byte(nil), block.Bytes...)
	der[len(der)-1] ^= 0x01
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
