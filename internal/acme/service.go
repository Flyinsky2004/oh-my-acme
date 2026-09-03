// Package acme obtains and renews TLS certificates using the ACME protocol
// (RFC 8555) with DNS-01 validation through Cloudflare. Only the requested
// _acme-challenge TXT value is created and, after validation, only the records
// this package created (by Cloudflare record ID) are removed — never a
// name-based bulk delete. It supports Let's Encrypt and any RFC 8555 CA
// directory URL the operating system trust store accepts (no EAB, no custom
// root CA bundle, matching the requested minimal scope).
package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/Flyinsky2004/oh-my-acme/internal/domain"
	"github.com/cloudflare/cloudflare-go/v4"
	"github.com/cloudflare/cloudflare-go/v4/option"
	xacme "golang.org/x/crypto/acme"
)

const userAgent = "oh-my-acme/1.0"

// Service provides certificate issuance (an umbrella for Issuer instances
// created per CA).
type Service struct {
	log *slog.Logger
}

// New returns an ACME service.
func New(log *slog.Logger) *Service {
	if log == nil {
		log = slog.Default()
	}
	return &Service{log: log}
}

// issueResult carries the freshly issued certificate material.
type issueResult struct {
	VersionID    string
	Serial       string
	IssuedAt     time.Time
	ExpiresAt    time.Time
	CertPEM      []byte
	CAPEM        []byte
	FullchainPEM []byte
	PrivateKey   []byte
	KeyType      domain.KeyType
}

// dnsRecord is a created TXT record awaiting cleanup by Cloudflare record ID.
type dnsRecord struct {
	RecordID string
	ZoneID   string
	Name     string
	Value    string
}

// IssueOptions configures a single issuance.
type IssueOptions struct {
	CertID       string
	RootDomain   string
	SAN          []string
	Credential   domain.CloudflareCredential
	DirectoryURL string
	AccountEmail string
	KeyType      domain.KeyType
	DNSSleepSecs int
	Logf         func(format string, args ...any)
}

func (o IssueOptions) logf(format string, args ...any) {
	if o.Logf != nil {
		o.Logf(format, args...)
	}
}

// Issuer creates certificates for a single CA directory.
type Issuer struct {
	client *xacme.Client
	dirURL string
	s      *Service
}

// NewIssuer builds an Issuer for a CA directory using a persisted account key.
func NewIssuer(log *slog.Logger, dirURL string, accountKey crypto.Signer) (*Issuer, error) {
	if accountKey == nil {
		return nil, fmt.Errorf("account key is nil")
	}
	return &Issuer{
		client: &xacme.Client{
			Key:          accountKey,
			DirectoryURL: dirURL,
			UserAgent:    userAgent,
			HTTPClient:   &http.Client{Timeout: 30 * time.Second},
		},
		dirURL: dirURL,
		s:      &Service{log: log},
	}, nil
}

// GenerateAccountKey builds a fresh EC account key and returns it as PEM.
func GenerateAccountKey() ([]byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}

// AccountSigner parses a PEM EC/RSA private key into a crypto.Signer for use
// as the ACME account key.
func AccountSigner(pemBytes []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("invalid account key PEM")
	}
	switch block.Type {
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		signer, ok := k.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("PKCS#8 key is not a signer (%T)", k)
		}
		return signer, nil
	}
	return nil, fmt.Errorf("unsupported account key type %q", block.Type)
}

// register ensures the account is registered with the CA. Register returns
// ErrAccountAlreadyExists for a persisted account key, which is a successful
// reusable-account state rather than an issuance failure.
func (i *Issuer) register(ctx context.Context, email string) error {
	account := &xacme.Account{}
	if email != "" {
		account.Contact = []string{"mailto:" + email}
	}
	_, err := i.client.Register(ctx, account, xacme.AcceptTOS)
	if err != nil && !errors.Is(err, xacme.ErrAccountAlreadyExists) {
		return fmt.Errorf("acme account register: %w", err)
	}
	return nil
}

// Issue runs the full DNS-01 issuance flow. It returns the certificate
// material and the TXT records it created (so the caller can clean them up
// even if a later step fails).
func (i *Issuer) Issue(ctx context.Context, opts IssueOptions) (issueResult, []dnsRecord, error) {
	// Register account (idempotent for an existing key).
	opts.logf("正在注册或加载 ACME 账户")
	if err := i.register(ctx, opts.AccountEmail); err != nil {
		return issueResult{}, nil, err
	}
	opts.logf("ACME 账户准备完成")

	// New order for all SANs (including wildcard).
	opts.logf("正在创建 ACME Order")
	ids := make([]xacme.AuthzID, 0, len(opts.SAN))
	for _, d := range opts.SAN {
		ids = append(ids, xacme.AuthzID{Type: "dns", Value: d})
	}
	order, err := i.client.AuthorizeOrder(ctx, ids)
	if err != nil {
		return issueResult{}, nil, fmt.Errorf("authorize order: %w", err)
	}
	opts.logf("ACME Order 创建成功")

	cfclient := cloudflare.NewClient(option.WithAPIToken(opts.Credential.Token))
	var created []dnsRecord
	// Always remove every TXT record we created, regardless of how the issue
	// ends (success, validation failure, or timeout). On success the caller
	// still receives the created list for audit; the records are gone.
	defer func() {
		if len(created) > 0 {
			opts.logf("正在清理 Cloudflare TXT 记录")
		}
		for _, r := range created {
			if _, err := deleteRecord(context.Background(), cfclient, r.RecordID, r.ZoneID); err != nil {
				i.s.log.Warn("failed to remove challenge TXT record", "record_id", r.RecordID, "err", err)
				opts.logf("TXT 记录清理失败: %v", err)
				continue
			}
			opts.logf("TXT 记录清理成功: %s", r.Name)
		}
	}()

	// Stage 1: create all TXT records and collect challenges.
	opts.logf("正在准备 DNS-01 验证")
	var challenges []*xacme.Challenge
	var wsValidation = make(map[string][]string) // txtName -> expected values
	for _, authzURL := range order.AuthzURLs {
		authz, err := i.client.GetAuthorization(ctx, authzURL)
		if err != nil {
			return issueResult{}, created, err
		}
		if authz.Status == xacme.StatusValid {
			continue
		}
		for _, ch := range authz.Challenges {
			if ch.Type != "dns-01" {
				continue
			}
			value, err := i.client.DNS01ChallengeRecord(ch.Token)
			if err != nil {
				return issueResult{}, created, err
			}
			name := txtName(authz.Identifier.Value)
			opts.logf("正在创建 Cloudflare TXT 记录: %s", name)
			rec, err := createRecord(ctx, cfclient, opts.Credential.ZoneID, name, value)
			if err != nil {
				return issueResult{}, nil, err
			}
			opts.logf("Cloudflare TXT 记录创建成功: %s", name)
			created = append(created, rec)
			wsValidation[name] = append(wsValidation[name], value)
			challenges = append(challenges, ch)
		}
	}

	if len(challenges) == 0 {
		// All authorizations already satisfied; order may already be ready.
		// Fall through to finalize below. Nothing to clean up.
	}

	// Stage 2: wait for propagation (acme.sh style).
	if err := i.waitPropagation(ctx, opts, wsValidation); err != nil {
		return issueResult{}, nil, err
	}

	// Stage 3: tell the CA we're ready (accept) then wait for each authorisation.
	opts.logf("正在通知 ACME CA 开始验证")
	for _, ch := range challenges {
		if _, err := i.client.Accept(ctx, ch); err != nil {
			return issueResult{}, created, err
		}
	}
	for _, authzURL := range order.AuthzURLs {
		authz, err := i.client.WaitAuthorization(ctx, authzURL)
		if err != nil {
			return issueResult{}, created, fmt.Errorf("wait authorization: %w", err)
		}
		_ = authz
	}
	opts.logf("域名验证成功")

	// Stage 4: build CSR and finalize.
	opts.logf("正在生成新的 %s 私钥和 CSR", opts.KeyType)
	csrDER, privKey, keyType, err := buildCSR(opts.KeyType, opts.SAN)
	if err != nil {
		return issueResult{}, created, err
	}
	opts.logf("正在请求 ACME CA 签发证书")
	chain, _, err := i.client.CreateOrderCert(ctx, order.FinalizeURL, csrDER, true)
	if err != nil {
		return issueResult{}, created, fmt.Errorf("finalize order: %w", err)
	}
	opts.logf("ACME CA 已返回证书")

	// Verify the returned chain, split leaf vs issuer, assemble PEM files.
	certX509, capem, certPEM, fullchainPEM, err := splitAndMarshalChain(chain)
	if err != nil {
		return issueResult{}, created, err
	}

	// Persist the private key (EC key for EC types, PKCS1 for RSA).
	privPEM, err := marshalPrivateKey(privKey, keyType)
	if err != nil {
		return issueResult{}, created, err
	}

	return issueResult{
		Serial:       certX509.SerialNumber.Text(16),
		IssuedAt:     certX509.NotBefore,
		ExpiresAt:    certX509.NotAfter,
		CertPEM:      certPEM,
		CAPEM:        capem,
		FullchainPEM: fullchainPEM,
		PrivateKey:   privPEM,
		KeyType:      keyType,
	}, created, nil
}
