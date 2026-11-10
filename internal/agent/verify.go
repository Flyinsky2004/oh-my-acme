package agent

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Flyinsky2004/oh-my-acme/internal/protocol"
)

// verifyCertMaterial validates the complete certificate material pushed by the
// server before any live file is touched. It checks:
//
//   - fullchain.pem is strict PEM and every block is a parseable certificate;
//   - cert.pem is exactly one certificate and is the same DER as the first
//     certificate of fullchain.pem;
//   - the private key matches the leaf certificate;
//   - the leaf is currently valid, is not a CA, is usable for TLS server auth,
//     and covers both the root domain and its wildcard;
//   - the chain order is leaf -> issuer -> ... and every signature verifies;
//   - x509.Verify enforces path constraints (MaxPathLen, name constraints,
//     intermediate EKU nesting, unknown critical extensions) using the last
//     pushed chain certificate as the trust anchor;
//   - ca.pem, when present, is exactly the issuer chain from fullchain.pem.
//
// Trust is anchored in the authenticated server push, not in the host's public
// root store, so private CAs and multi-CA ACME chains work. The last chain
// certificate is the anchor even when it is an intermediate (the root is
// commonly omitted from fullchain.pem). A single self-signed leaf is accepted
// as the whole chain for private self-signed deployments.
//
// Validity is checked with no clock skew, matching x509.Verify's CurrentTime
// semantics: the agent and issuer clocks must be synchronized.
//
// The agent's own mTLS CA (Config.ServerCAFile) is deliberately not used here:
// it authenticates the server connection and must never be confused with the
// deployed chain.
func verifyCertMaterial(req protocol.DeployRequest) error {
	chain, err := parseCertChainStrict([]byte(req.FullchainPEM))
	if err != nil {
		return fmt.Errorf("fullchain.pem: %w", err)
	}
	if len(chain) == 0 {
		return errors.New("fullchain.pem: no certificates")
	}
	leaf := chain[0]

	certOnly, err := parseCertChainStrict([]byte(req.CertPEM))
	if err != nil {
		return fmt.Errorf("cert.pem: %w", err)
	}
	if len(certOnly) != 1 {
		return fmt.Errorf("cert.pem: expected exactly one certificate, got %d", len(certOnly))
	}
	if !bytes.Equal(certOnly[0].Raw, leaf.Raw) {
		return errors.New("cert.pem does not match the first certificate in fullchain.pem")
	}

	if err := keyMatches(req.PrivateKeyPEM, leaf); err != nil {
		return err
	}

	now := time.Now()
	for i, cert := range chain {
		if err := checkCriticalExtensions(cert, fmt.Sprintf("chain certificate %d", i)); err != nil {
			return err
		}
	}
	if err := checkLeaf(leaf, req.RootDomain, now); err != nil {
		return err
	}
	if err := checkChain(chain, now); err != nil {
		return err
	}
	if err := verifyChain(chain, now); err != nil {
		return err
	}
	if err := checkCAChain(chain, req.CAPEM); err != nil {
		return err
	}
	return nil
}

// parseCertChainStrict parses every PEM block in data as a certificate. It
// rejects non-certificate blocks, PEM headers, and any non-whitespace data
// before/between/after blocks. An empty input returns an empty slice.
func parseCertChainStrict(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := data
	for {
		block, after, err := decodeOnePEMStrict(rest)
		if err != nil {
			return nil, err
		}
		if block == nil {
			break
		}
		if len(block.Headers) != 0 {
			return nil, fmt.Errorf("unexpected PEM headers on %q block", block.Type)
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("unexpected PEM block %q (want CERTIFICATE)", block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}
		certs = append(certs, cert)
		rest = after
	}
	return certs, nil
}

// decodeOnePEMStrict decodes exactly the first PEM block in data. Unlike
// pem.Decode, it never skips a malformed block to reach a later valid one:
// it locates the first BEGIN line, requires the matching END line, rejects a
// second BEGIN inside that span, and fails if the block does not decode.
// It returns (nil, nil, nil) when only whitespace remains.
func decodeOnePEMStrict(data []byte) (*pem.Block, []byte, error) {
	begin := bytes.Index(data, []byte("-----BEGIN "))
	if begin < 0 {
		if len(bytes.TrimSpace(data)) != 0 {
			return nil, nil, errors.New("trailing non-PEM data")
		}
		return nil, nil, nil
	}
	if len(bytes.TrimSpace(data[:begin])) != 0 {
		return nil, nil, errors.New("non-PEM data before PEM block")
	}
	if begin > 0 && data[begin-1] != '\n' {
		return nil, nil, errors.New("PEM BEGIN marker is not at the start of a line")
	}

	beginNL := bytes.IndexByte(data[begin:], '\n')
	if beginNL < 0 {
		return nil, nil, errors.New("PEM BEGIN line is not terminated")
	}
	beginLineEnd := begin + beginNL
	beginLine := bytes.TrimSuffix(data[begin:beginLineEnd], []byte("\r"))

	const beginPrefix = "-----BEGIN "
	const dashes = "-----"
	if !bytes.HasPrefix(beginLine, []byte(beginPrefix)) || !bytes.HasSuffix(beginLine, []byte(dashes)) {
		return nil, nil, errors.New("malformed PEM BEGIN line")
	}
	typ := string(beginLine[len(beginPrefix) : len(beginLine)-len(dashes)])
	if typ == "" || strings.Contains(typ, "-") {
		return nil, nil, errors.New("malformed PEM type")
	}

	endRel := bytes.Index(data[beginLineEnd:], []byte("-----END "))
	if endRel < 0 {
		return nil, nil, errors.New("PEM block has no END marker")
	}
	end := beginLineEnd + endRel
	if data[end-1] != '\n' {
		return nil, nil, errors.New("PEM END marker is not at the start of a line")
	}
	endNL := bytes.IndexByte(data[end:], '\n')
	endLineEnd := len(data)
	if endNL >= 0 {
		endLineEnd = end + endNL + 1
	}
	endLine := bytes.TrimSuffix(data[end:endLineEnd], []byte("\n"))
	endLine = bytes.TrimSuffix(endLine, []byte("\r"))
	wantEnd := "-----END " + typ + "-----"
	if string(endLine) != wantEnd {
		return nil, nil, fmt.Errorf("PEM END line %q does not match BEGIN type %q", endLine, typ)
	}
	if bytes.Contains(data[begin+len(beginPrefix):end], []byte("-----BEGIN ")) {
		return nil, nil, errors.New("nested PEM BEGIN before END")
	}

	block, _ := pem.Decode(data[begin:endLineEnd])
	if block == nil {
		return nil, nil, errors.New("invalid PEM block")
	}
	if block.Type != typ {
		return nil, nil, fmt.Errorf("PEM type mismatch: BEGIN %q, decoded %q", typ, block.Type)
	}
	return block, data[endLineEnd:], nil
}

// checkLeaf validates the leaf's validity window, purpose, and names. now is
// shared with x509.Verify so the time policy is consistent.
func checkLeaf(leaf *x509.Certificate, root string, now time.Time) error {
	if root == "" {
		return errors.New("certificate: root domain is empty")
	}
	if now.Before(leaf.NotBefore) {
		return fmt.Errorf("certificate not yet valid (not before %s)", leaf.NotBefore.UTC().Format(time.RFC3339))
	}
	if !now.Before(leaf.NotAfter) {
		return fmt.Errorf("certificate expired (not after %s)", leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	if leaf.IsCA {
		return errors.New("leaf certificate is a CA certificate")
	}
	if leaf.KeyUsage != 0 && leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return errors.New("leaf certificate is not valid for digital signatures")
	}
	if len(leaf.ExtKeyUsage) > 0 {
		ok := false
		for _, u := range leaf.ExtKeyUsage {
			if u == x509.ExtKeyUsageServerAuth || u == x509.ExtKeyUsageAny {
				ok = true
				break
			}
		}
		if !ok {
			return errors.New("leaf certificate is not valid for TLS server authentication")
		}
	}
	if !hasSAN(leaf, root) {
		return fmt.Errorf("certificate does not cover %s", root)
	}
	if !hasSAN(leaf, "*."+root) {
		return fmt.Errorf("certificate does not cover *.%s", root)
	}
	return nil
}

// checkCriticalExtensions rejects certificates carrying critical extensions the
// Go parser did not understand. x509.Verify also enforces this for multi-cert
// chains; checking here gives a clear error and covers the single self-signed
// leaf case, which does not go through Verify.
func checkCriticalExtensions(cert *x509.Certificate, label string) error {
	if len(cert.UnhandledCriticalExtensions) != 0 {
		return fmt.Errorf("%s has unhandled critical extension(s): %v", label, cert.UnhandledCriticalExtensions)
	}
	return nil
}

// checkChain verifies the order and signatures of the presented chain. A
// single self-signed certificate is accepted (private self-signed CA use case).
// A multi-certificate chain may end at an intermediate (the root is commonly
// omitted from fullchain.pem); every presented signature must still verify.
func checkChain(chain []*x509.Certificate, now time.Time) error {
	if len(chain) == 1 {
		return checkSelfSigned(chain[0])
	}
	for i := 0; i < len(chain)-1; i++ {
		child, parent := chain[i], chain[i+1]
		if !bytes.Equal(child.RawIssuer, parent.RawSubject) {
			return fmt.Errorf("chain order invalid: certificate %d issuer does not match certificate %d subject", i, i+1)
		}
		if !parent.IsCA {
			return fmt.Errorf("chain certificate %d is not a CA certificate", i+1)
		}
		if parent.KeyUsage != 0 && parent.KeyUsage&x509.KeyUsageCertSign == 0 {
			return fmt.Errorf("chain certificate %d is not allowed to sign certificates", i+1)
		}
		if now.Before(parent.NotBefore) {
			return fmt.Errorf("chain certificate %d is not yet valid", i+1)
		}
		if !now.Before(parent.NotAfter) {
			return fmt.Errorf("chain certificate %d has expired", i+1)
		}
		if err := child.CheckSignatureFrom(parent); err != nil {
			return fmt.Errorf("chain signature %d -> %d: %w", i, i+1, err)
		}
	}
	last := chain[len(chain)-1]
	if bytes.Equal(last.RawIssuer, last.RawSubject) {
		if err := checkSelfSigned(last); err != nil {
			return fmt.Errorf("root certificate: %w", err)
		}
	}
	return nil
}

// verifyChain runs x509.Verify with the last pushed certificate as the trust
// anchor. This enforces path length, name constraints, intermediate EKU
// nesting, and unknown critical extensions without depending on the host's
// public root store. A single self-signed leaf has no path to constrain; its
// self-signature was already checked by checkChain.
func verifyChain(chain []*x509.Certificate, now time.Time) error {
	if len(chain) == 1 {
		return nil
	}
	roots := x509.NewCertPool()
	roots.AddCert(chain[len(chain)-1])
	intermediates := x509.NewCertPool()
	for _, cert := range chain[1 : len(chain)-1] {
		intermediates.AddCert(cert)
	}
	if _, err := chain[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return fmt.Errorf("certificate chain verification: %w", err)
	}
	return nil
}

// checkCAChain ensures ca.pem is consistent with the issuer part of the
// fullchain. An empty ca.pem is accepted when the fullchain carries the chain
// itself; when present it must match fullchain[1:] exactly.
func checkCAChain(chain []*x509.Certificate, caPEM string) error {
	ca, err := parseCertChainStrict([]byte(caPEM))
	if err != nil {
		return fmt.Errorf("ca.pem: %w", err)
	}
	if len(ca) == 0 {
		return nil
	}
	if len(chain) == 1 {
		if len(ca) != 1 || !bytes.Equal(ca[0].Raw, chain[0].Raw) {
			return errors.New("ca.pem does not match the self-signed certificate chain")
		}
		return nil
	}
	if len(ca) != len(chain)-1 {
		return fmt.Errorf("ca.pem has %d certificate(s), fullchain.pem has %d issuer certificate(s)", len(ca), len(chain)-1)
	}
	for i := range ca {
		if !bytes.Equal(ca[i].Raw, chain[i+1].Raw) {
			return fmt.Errorf("ca.pem certificate %d does not match fullchain.pem certificate %d", i, i+1)
		}
	}
	return nil
}

func checkSelfSigned(cert *x509.Certificate) error {
	if !bytes.Equal(cert.RawIssuer, cert.RawSubject) {
		return errors.New("certificate is not self-signed")
	}
	if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
		return fmt.Errorf("self-signature invalid: %w", err)
	}
	return nil
}

func hasSAN(cert *x509.Certificate, domain string) bool {
	for _, d := range cert.DNSNames {
		if strings.EqualFold(d, domain) {
			return true
		}
	}
	return false
}

// keyMatches verifies the private key corresponds to the certificate public
// key. Supports EC, RSA, and PKCS#8 (including Ed25519) keys in PEM form.
func keyMatches(keyPEM string, cert *x509.Certificate) error {
	key, err := parsePrivateKeyStrict([]byte(keyPEM))
	if err != nil {
		return err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return errors.New("private key cannot sign")
	}
	keyPub, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return fmt.Errorf("marshal private key public key: %w", err)
	}
	certPub, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return fmt.Errorf("marshal certificate public key: %w", err)
	}
	if !bytes.Equal(keyPub, certPub) {
		return errors.New("private key does not match certificate")
	}
	return nil
}

// parsePrivateKeyStrict parses exactly one unencrypted private-key PEM block
// and rejects headers, a malformed first block, or trailing data.
func parsePrivateKeyStrict(data []byte) (any, error) {
	block, rest, err := decodeOnePEMStrict(data)
	if err != nil {
		return nil, err
	}
	if block == nil {
		return nil, errors.New("private key is not PEM")
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("private key has trailing non-PEM data")
	}
	if len(block.Headers) != 0 {
		return nil, errors.New("private key has unexpected PEM headers")
	}
	switch block.Type {
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		return x509.ParsePKCS8PrivateKey(block.Bytes)
	case "ENCRYPTED PRIVATE KEY":
		return nil, errors.New("encrypted private keys are not supported")
	default:
		return nil, fmt.Errorf("unsupported private key type %q", block.Type)
	}
}
