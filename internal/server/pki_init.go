package server

import (
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/Flyinsky2004/oh-my-acme/internal/pki"
)

// pkiFiles bundles the persisted PKI material paths.
type pkiFiles struct {
	caCert  string
	caKey   string
	srvCert string
	srvKey  string
	cliCert string
	cliKey  string
}

// EnsurePKI loads existing PKI files from pkiDir, or generates a fresh private
// CA plus the server's identity (control-port) and client-identity (push)
// certificates on first run. CA cert + serial identities are written 0644;
// the CA key and private keys are 0600. This material never enters state.json.
func EnsurePKI(pkiDir string) (*pki.CA, *pki.KeyPair, *pki.KeyPair, error) {
	if err := os.MkdirAll(pkiDir, 0o700); err != nil {
		return nil, nil, nil, err
	}
	f := pkiFiles{
		caCert:  filepath.Join(pkiDir, "ca.crt"),
		caKey:   filepath.Join(pkiDir, "ca.key"),
		srvCert: filepath.Join(pkiDir, "server.crt"),
		srvKey:  filepath.Join(pkiDir, "server.key"),
		cliCert: filepath.Join(pkiDir, "server-client.crt"),
		cliKey:  filepath.Join(pkiDir, "server-client.key"),
	}

	ca, err := loadOrCreateCA(f)
	if err != nil {
		return nil, nil, nil, err
	}

	serverIPs, err := serverIPs()
	if err != nil {
		return nil, nil, nil, err
	}

	srvID, err := loadOrCreateIdentity(f.srvCert, f.srvKey, func() (*pki.KeyPair, error) {
		return ca.SignServerIdentity(serverIPs)
	})
	if err != nil {
		return nil, nil, nil, err
	}

	cliID, err := loadOrCreateIdentity(f.cliCert, f.cliKey, func() (*pki.KeyPair, error) {
		return ca.SignServerClientIdentity()
	})
	if err != nil {
		return nil, nil, nil, err
	}

	return ca, srvID, cliID, nil
}

func loadOrCreateCA(f pkiFiles) (*pki.CA, error) {
	caCert, err := os.ReadFile(f.caCert)
	if err == nil {
		caKey, kerr := os.ReadFile(f.caKey)
		if kerr != nil {
			return nil, fmt.Errorf("ca key missing: %w", kerr)
		}
		cert, cerr := pki.ParseCACert(caCert)
		if cerr != nil {
			return nil, cerr
		}
		key, kerr := pki.ParseCAKey(caKey)
		if kerr != nil {
			return nil, kerr
		}
		return &pki.CA{Cert: cert, Key: key}, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	ca, err := pki.NewCA("oh-my-acme-ca")
	if err != nil {
		return nil, err
	}
	if err := writeFileMode(f.caKey, ca.EncodeKey(), 0o600); err != nil {
		return nil, err
	}
	if err := writeFileMode(f.caCert, ca.EncodeCA(), 0o644); err != nil {
		return nil, err
	}
	return ca, nil
}

func loadOrCreateIdentity(certPath, keyPath string, makePair func() (*pki.KeyPair, error)) (*pki.KeyPair, error) {
	certPEM, rerr := os.ReadFile(certPath)
	if rerr == nil {
		keyPEM, kerr := os.ReadFile(keyPath)
		if kerr != nil {
			return nil, kerr
		}
		cert, cerr := pki.ParseCertificatePEM(certPEM)
		if cerr != nil {
			return nil, cerr
		}
		return &pki.KeyPair{CertPEM: certPEM, KeyPEM: keyPEM, Cert: cert}, nil
	}
	if !os.IsNotExist(rerr) {
		return nil, rerr
	}
	kp, err := makePair()
	if err != nil {
		return nil, err
	}
	if err := writeFileMode(keyPath, kp.KeyPEM, 0o600); err != nil {
		return nil, err
	}
	if err := writeFileMode(certPath, kp.CertPEM, 0o644); err != nil {
		return nil, err
	}
	return kp, nil
}

func writeFileMode(path string, data []byte, mode os.FileMode) error {
	return os.WriteFile(path, data, mode)
}

// serverIPs returns the non-loopback IPv4 addresses of the host, falling back
// to the loopback address when none is found.
func serverIPs() ([]net.IP, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	var out []net.IP
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP.To4() != nil && !ipnet.IP.IsLoopback() {
			out = append(out, ipnet.IP)
		}
	}
	if len(out) == 0 {
		out = append(out, net.ParseIP("127.0.0.1"))
	}
	return out, nil
}
