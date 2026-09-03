package agent

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Flyinsky2004/oh-my-acme/internal/protocol"
)

// verifyCertMaterial parses the pushed leaf certificate and private key,
// checks the certificate is currently valid, covers the expected domain and
// its wildcard, and that the private key matches the certificate public key.
// All checks happen before any live file is touched.
func verifyCertMaterial(req protocol.DeployRequest) error {
	leaf, err := parseLeaf(req.CertPEM)
	if err != nil {
		return err
	}
	now := time.Now()
	if now.Before(leaf.NotBefore.Add(-5 * time.Minute)) {
		return fmt.Errorf("certificate not yet valid")
	}
	if now.After(leaf.NotAfter) {
		return fmt.Errorf("certificate expired")
	}

	root := req.RootDomain
	if !hasSAN(leaf, root) {
		return fmt.Errorf("certificate does not cover %s", root)
	}
	if !hasSAN(leaf, "*."+root) {
		return fmt.Errorf("certificate does not cover *.%s", root)
	}

	if err := keyMatches(req.PrivateKeyPEM, leaf); err != nil {
		return err
	}
	return nil
}

func parseLeaf(pemBytes string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemBytes))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("cert is not PEM")
	}
	return x509.ParseCertificate(block.Bytes)
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
// key. Supports EC and RSA keys in PEM form.
func keyMatches(keyPEM string, cert *x509.Certificate) error {
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		return errors.New("private key is not PEM")
	}

	var pub any
	switch block.Type {
	case "EC PRIVATE KEY":
		k, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return err
		}
		pub = k.Public()
	case "RSA PRIVATE KEY":
		k, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return err
		}
		pub = k.Public()
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return err
		}
		switch k := k.(type) {
		case interface{ Public() any }:
			pub = k.Public()
			// fall through
		}
	default:
		return fmt.Errorf("unsupported private key type %q", block.Type)
	}

	switch certPub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		kp, ok := pub.(*rsa.PublicKey)
		if !ok || kp.N.Cmp(certPub.N) != 0 || kp.E != certPub.E {
			return errors.New("private key does not match certificate (RSA)")
		}
	default:
		// EC: compare by marshalling public keys (digest equality is a close
		// proxy for identity of the EC point).
		pubDER, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			return err
		}
		certPubDER, err := x509.MarshalPKIXPublicKey(certPub)
		if err != nil {
			return err
		}
		if string(pubDER) != string(certPubDER) {
			return errors.New("private key does not match certificate (EC)")
		}
	}
	return nil
}
