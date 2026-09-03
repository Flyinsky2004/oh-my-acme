package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Flyinsky2004/oh-my-acme/internal/acme"
	"github.com/Flyinsky2004/oh-my-acme/internal/domain"
	"github.com/Flyinsky2004/oh-my-acme/internal/protocol"
	"github.com/Flyinsky2004/oh-my-acme/internal/store"
)

var errNotFound = errors.New("not found")

// --- Certificates ---

// CreateCertificate records a certificate configuration (no issuance yet).
func (s *Server) CreateCertificate(root, credID, caID string, keyType domain.KeyType, targetAgents []string) (string, error) {
	root = normalizeDomain(root)
	if !validDomain(root) {
		return "", fmt.Errorf("invalid root domain %q", root)
	}
	id, err := store.NewID()
	if err != nil {
		return "", err
	}
	san := []string{root, "*." + root}
	err = s.st.WithState(true, func(st *domain.State) error {
		if keyType == "" {
			keyType = st.Config.DefaultKeyType
		}
		if caID == "" {
			caID = st.Config.DefaultACMEID
		}
		if _, ok := st.CAs[caID]; !ok {
			return fmt.Errorf("acme ca %q not found", caID)
		}
		if _, ok := st.Credentials[credID]; !ok {
			return fmt.Errorf("cloudflare credential %q not found", credID)
		}
		st.Certificates[id] = &domain.Certificate{
			ID:           id,
			RootDomain:   root,
			SanDomains:   san,
			CredentialID: credID,
			ACMEID:       caID,
			KeyType:      keyType,
			Enabled:      true,
			TargetAgents: append([]string(nil), targetAgents...),
			Deploys:      map[string]*domain.AgentDeployState{},
			IssueStatus:  domain.StatusPending,
			CreatedAt:    time.Now(),
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return id, nil
}

// Issue performs an ACME issuance (new private key, new order) and, on
// success, swaps the current version. It does not deploy.
func (s *Server) Issue(ctx context.Context, certID string) error {
	st := s.st.State()
	cert := st.Certificates[certID]
	if cert == nil {
		return errNotFound
	}
	ca := st.CAs[cert.ACMEID]
	cred := st.Credentials[cert.CredentialID]
	if ca == nil || !ca.Enabled {
		return fmt.Errorf("acme ca not enabled")
	}
	if cred == nil || !cred.Enabled {
		return fmt.Errorf("cloudflare credential not enabled")
	}

	s.markIssueStatus(certID, domain.StatusRunning, "")

	issuer, err := s.issuerFor(cert.ACMEID, ca.DirectoryURL, st.Config.ACMEAccountEmail)
	if err != nil {
		s.markIssueStatus(certID, domain.StatusFailed, err.Error())
		return err
	}
	res, created, err := issuer.Issue(ctx, acme.IssueOptions{
		CertID:       certID,
		RootDomain:   cert.RootDomain,
		SAN:          cert.SanDomains,
		Credential:   *cred,
		DirectoryURL: ca.DirectoryURL,
		AccountEmail: st.Config.ACMEAccountEmail,
		KeyType:      cert.KeyType,
		DNSSleepSecs: st.Config.DNSSleepSeconds,
	})
	if err != nil {
		s.markIssueStatus(certID, domain.StatusFailed, err.Error())
		return fmt.Errorf("issue %s: %w", cert.RootDomain, err)
	}
	// Resolve the account key now that we have an issuer.
	_ = created // challenge records are cleaned in-process by the ACSM service.

	versionID, err := store.NewID()
	if err != nil {
		return err
	}
	v := domain.CertificateVersion{ID: versionID, IssuedAt: res.IssuedAt, ExpiresAt: res.ExpiresAt, Serial: res.Serial}
	v, err = s.st.WriteCertVersion(certID, v, res.CertPEM, res.CAPEM, res.FullchainPEM, res.PrivateKey)
	if err != nil {
		s.markIssueStatus(certID, domain.StatusFailed, err.Error())
		return err
	}
	var old *domain.CertificateVersion
	err = s.st.WithState(true, func(st *domain.State) error {
		c := st.Certificates[certID]
		old = c.Current
		c.Current = &v
		c.IssueStatus = domain.StatusSuccess
		c.LastError = ""
		c.Deploys = map[string]*domain.AgentDeployState{}
		return nil
	})
	if err == nil {
		if old != nil {
			_ = s.st.RemoveCertVersion(certID, old.ID)
		}
	}
	return err
}

// issuerFor returns an Issuer for a CA, creating and persisting the per-CA ACME
// account key on first use.
func (s *Server) issuerFor(caID, dirURL, accountEmail string) (*acme.Issuer, error) {
	rel := acmeAccountKeyPath(caID)
	keyPEM, err := s.st.ReadFile(rel)
	if err != nil {
		keyPEM, err = acme.GenerateAccountKey()
		if err != nil {
			return nil, err
		}
		if err := s.st.WriteSecretFile(rel, keyPEM); err != nil {
			return nil, err
		}
	}
	signer, err := acme.AccountSigner(keyPEM)
	if err != nil {
		return nil, err
	}
	return acme.NewIssuer(s.log, dirURL, signer)
}

func (s *Server) markIssueStatus(certID string, status domain.OperationStatus, msg string) {
	_ = s.st.WithState(true, func(st *domain.State) error {
		if c := st.Certificates[certID]; c != nil {
			c.IssueStatus = status
			c.LastError = msg
		}
		return nil
	})
}

// --- Deployment ---

// DeployCert pushes the certificate's current version to a single agent.
func (s *Server) DeployCert(ctx context.Context, certID, agentID string) error {
	st := s.st.State()
	cert := st.Certificates[certID]
	agent := st.Agents[agentID]
	if cert == nil || cert.Current == nil {
		return errors.New("certificate has no issued version")
	}
	if agent == nil {
		return errors.New("agent not found")
	}
	req, err := buildDeployRequest(s.st, cert)
	if err != nil {
		return err
	}
	resp, err := s.pushCert(ctx, agent, req)
	if err != nil {
		s.recordDeploy(certID, agentID, false, "", err.Error())
		return err
	}
	if !resp.Success {
		s.recordDeploy(certID, agentID, false, cert.Current.ID, resp.Error)
		return fmt.Errorf("agent deploy failed: %s", resp.Error)
	}
	s.recordDeploy(certID, agentID, true, cert.Current.ID, "")
	return nil
}

// DeployAll pushes the current version to every target agent, recording each
// result independently. Returns the first error (other agents still attempted).
func (s *Server) DeployAll(ctx context.Context, certID string) error {
	st := s.st.State()
	cert := st.Certificates[certID]
	if cert == nil {
		return errNotFound
	}
	var firstErr error
	for _, agentID := range cert.TargetAgents {
		if err := s.DeployCert(ctx, certID, agentID); err != nil {
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

// buildDeployRequest loads version PEM files and assembles a DeployRequest.
func buildDeployRequest(st *store.Store, cert *domain.Certificate) (protocol.DeployRequest, error) {
	certPEM, caPEM, fullchain, priv, err := st.ReadCertVersion(*cert.Current)
	if err != nil {
		return protocol.DeployRequest{}, err
	}
	return protocol.DeployRequest{
		CertificateID: cert.ID,
		RootDomain:    cert.RootDomain,
		VersionID:     cert.Current.ID,
		CertPEM:       string(certPEM),
		CAPEM:         string(caPEM),
		FullchainPEM:  string(fullchain),
		PrivateKeyPEM: string(priv),
	}, nil
}

// pushCert sends the deploy request to the agent over mTLS.
func (s *Server) pushCert(ctx context.Context, agent *domain.Agent, req protocol.DeployRequest) (*protocol.DeployResponse, error) {
	u := fmt.Sprintf("https://%s:%d%s/deploy", agent.Address, agent.Port, protocol.AgentAPIPrefix)
	client := &http.Client{
		Timeout:   s.agentDialTimeout(),
		Transport: &http.Transport{TLSClientConfig: s.cliTLSCfg},
	}
	body, err := encodeJSON(req)
	if err != nil {
		return nil, err
	}
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, u, body)
	if err != nil {
		return nil, err
	}
	hreq.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(hreq)
	if err != nil {
		return nil, fmt.Errorf("push to %s: %w", agent.Address, err)
	}
	defer resp.Body.Close()
	var out protocol.DeployResponse
	if err := decodeJSON(resp.Body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// recordDeploy persists the per-agent deployment result.
func (s *Server) recordDeploy(certID, agentID string, success bool, versionID, msg string) {
	_ = s.st.WithState(true, func(st *domain.State) error {
		c := st.Certificates[certID]
		if c == nil {
			return nil
		}
		d := c.Deploys[agentID]
		if d == nil {
			d = &domain.AgentDeployState{AgentID: agentID}
			c.Deploys[agentID] = d
		}
		d.VersionID = versionID
		d.LastAttemptAt = time.Now()
		if success {
			d.Status = domain.StatusSuccess
			d.LastSuccessAt = time.Now()
			d.Error = ""
			d.RetryCount = 0
		} else {
			d.Status = domain.StatusFailed
			d.Error = msg
			d.RetryCount++
		}
		return nil
	})
}

// --- Helpers ---

func normalizeDomain(d string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
}

func validDomain(d string) bool {
	if len(d) == 0 || len(d) > 253 || strings.HasPrefix(d, "*.") {
		return false
	}
	for _, part := range strings.Split(d, ".") {
		if part == "" || len(part) > 63 {
			return false
		}
		for _, r := range part {
			if !(r == '-' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z')) {
				return false
			}
		}
	}
	return strings.Count(d, ".") >= 1
}

func acmeAccountKeyPath(caID string) string {
	return "acme-accounts/" + sanitizeID(caID) + "/account.key"
}

func sanitizeID(id string) string {
	id = strings.ReplaceAll(id, "/", "-")
	id = strings.ReplaceAll(id, "\\", "-")
	id = strings.ReplaceAll(id, "..", "-")
	if id == "" {
		return "default"
	}
	return id
}
