package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Flyinsky2004/oh-my-acme/internal/domain"
	"github.com/cloudflare/cloudflare-go/v4"
	"github.com/cloudflare/cloudflare-go/v4/dns"
)

const (
	dnsTTL            = 60 // short TTL for challenge records
	defaultPropagate  = 20 * time.Minute
	propagateInterval = 10 * time.Second
)

// txtName returns the _acme-challenge hostname for an identifier. For a
// wildcard "*.example.com" the challenge record lives at the apex name
// "_acme-challenge.example.com".
func txtName(identifier string) string {
	identifier = strings.TrimPrefix(identifier, "*.")
	return "_acme-challenge." + identifier
}

// createRecord inserts the TXT record in Cloudflare and returns the record it
// created (with the record ID) so it can be cleaned up later by ID.
func createRecord(ctx context.Context, cf *cloudflare.Client, zoneID, name, value string) (dnsRecord, error) {
	res, err := cf.DNS.Records.New(ctx, dns.RecordNewParams{
		ZoneID: cloudflare.String(zoneID),
		Body: dns.TXTRecordParam{
			Name:    cloudflare.String(name),
			Content: cloudflare.String(`"` + value + `"`),
			TTL:     cloudflare.F(dns.TTL(dnsTTL)),
			Type:    cloudflare.F(dns.TXTRecordTypeTXT),
		},
	})
	if err != nil {
		return dnsRecord{}, fmt.Errorf("cloudflare create TXT %q: %w", name, err)
	}
	return dnsRecord{RecordID: res.ID, ZoneID: zoneID, Name: name, Value: value}, nil
}

// deleteRecord removes a previously created TXT record by its Cloudflare
// record ID. It never deletes by name, so other TXT values are preserved.
func deleteRecord(ctx context.Context, cf *cloudflare.Client, recordID, zoneID string) (any, error) {
	res, err := cf.DNS.Records.Delete(ctx, recordID, dns.RecordDeleteParams{
		ZoneID: cloudflare.String(zoneID),
	})
	if err != nil {
		return nil, fmt.Errorf("cloudflare delete record %q: %w", recordID, err)
	}
	return res, nil
}

// waitPropagation waits for the challenge TXT values to be visible. If
// DNSSleepSecs > 0 it sleeps that long and returns (acme.sh --dnssleep).
// Otherwise it polls a public DNS-over-HTTPS JSON worker until the values are
// visible or the global timeout is reached, matching acme.sh's automatic check.
func (i *Issuer) waitPropagation(ctx context.Context, opts IssueOptions, expected map[string][]string) error {
	if len(expected) == 0 {
		return nil
	}
	if opts.DNSSleepSecs > 0 {
		opts.logf("固定等待 DNS 传播: %d 秒", opts.DNSSleepSecs)
		select {
		case <-time.After(time.Duration(opts.DNSSleepSecs) * time.Second):
			opts.logf("DNS 固定等待完成")
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	opts.logf("开始自动检测 DNS 传播")
	deadline := time.Now().Add(defaultPropagate)
	attempt := 0
	for {
		attempt++
		all := true
		for name, wants := range expected {
			vals, err := dohLookup(ctx, name)
			if err != nil {
				opts.logf("DNS 查询失败 (%s): %v", name, err)
				all = false
				break
			}
			// A wildcard + apex SAN pair share the same _acme-challenge name
			// but carry different values; every one must be present.
			for _, want := range wants {
				if !contains(vals, want) {
					opts.logf("DNS 尚未传播 (%s)，第 %d 次检查", name, attempt)
					all = false
					break
				}
			}
			if !all {
				break
			}
		}
		if all {
			opts.logf("DNS 记录已传播")
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for DNS propagation")
		}
		select {
		case <-time.After(propagateInterval):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// dohLookup queries a public DNS-over-HTTPS JSON API for TXT records.
func dohLookup(ctx context.Context, name string) ([]string, error) {
	u := "https://cloudflare-dns.com/dns-query?name=" + name + "&type=TXT"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out struct {
		Answer []struct {
			Type int    `json:"type"` // 16 == TXT
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return parseTXTAnswers(out.Answer), nil
}

// parseTXTAnswers extracts TXT record values from a DoH answer in their raw
// (unquoted) presentation form. RFC 1035 TXT data is returned by the JSON API
// wrapped in double quotes, e.g. `"ABC"`; strip them so callers compare against
// the raw challenge value, and drop anything that is not a TXT record.
func parseTXTAnswers(answers []struct {
	Type int    `json:"type"` // 16 == TXT
	Data string `json:"data"`
}) []string {
	var vals []string
	for _, a := range answers {
		if a.Type == 16 {
			vals = append(vals, strings.Trim(a.Data, `"`))
		}
	}
	return vals
}

func contains(vals []string, want string) bool {
	for _, v := range vals {
		if v == want {
			return true
		}
	}
	return false
}

// buildCSR generates a private key and a CSR for the given SAN domains.
func buildCSR(keyType domain.KeyType, san []string) (csrDER []byte, privKey any, resolved domain.KeyType, err error) {
	switch keyType {
	case domain.KeyTypeEC256, domain.KeyTypeEC384:
		curve := elliptic.P256()
		if keyType == domain.KeyTypeEC384 {
			curve = elliptic.P384()
		}
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return nil, nil, keyType, err
		}
		csrDER, err = createCSR(key, san)
		return csrDER, key, keyType, err
	case domain.KeyTypeRSA2048, domain.KeyTypeRSA4096:
		bits := 2048
		if keyType == domain.KeyTypeRSA4096 {
			bits = 4096
		}
		key, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			return nil, nil, keyType, err
		}
		csrDER, err = createCSR(key, san)
		return csrDER, key, keyType, err
	default:
		return nil, nil, keyType, fmt.Errorf("unsupported key type %s", keyType)
	}
}

func createCSR(key any, san []string) ([]byte, error) {
	tmpl := &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: san[0]},
		DNSNames:           san,
		SignatureAlgorithm: x509.SHA256WithRSA, // overridden for EC below
	}
	// Pick the correct signature algorithm per key type.
	if ec, ok := key.(*ecdsa.PrivateKey); ok {
		if ec.Curve == elliptic.P384() {
			tmpl.SignatureAlgorithm = x509.ECDSAWithSHA384
		} else {
			tmpl.SignatureAlgorithm = x509.ECDSAWithSHA256
		}
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return nil, err
	}
	return der, nil
}

// splitAndMarshalChain takes the certificate chain DER returned by the ACME
// server and splits it into the leaf certificate and issuer chain, returning
// their PEM encodings.
func splitAndMarshalChain(chain [][]byte) (leaf *x509.Certificate, caPEM, certPEM, fullchainPEM []byte, err error) {
	if len(chain) == 0 {
		return nil, nil, nil, nil, fmt.Errorf("empty certificate chain")
	}
	leaf, err = x509.ParseCertificate(chain[0])
	if err != nil {
		return nil, nil, nil, nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: chain[0]})
	// fullchain = leaf + issuer(s).
	fullchainPEM = certPEM
	caPEM = nil
	for _, der := range chain[1:] {
		fullchainPEM = append(fullchainPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
		caPEM = append(caPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	return leaf, caPEM, certPEM, fullchainPEM, nil
}

// marshalPrivateKey writes the generated private key to PEM.
func marshalPrivateKey(key any, keyType domain.KeyType) ([]byte, error) {
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		der, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
	case *rsa.PrivateKey:
		der := x509.MarshalPKCS1PrivateKey(k)
		return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}), nil
	}
	return nil, fmt.Errorf("unsupported private key type %T", key)
}
