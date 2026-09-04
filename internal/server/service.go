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
	"github.com/Flyinsky2004/oh-my-acme/internal/updater"
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

// UpdateCertificate edits an existing certificate's configuration. The issued
// version (if any) is left in place so already-deployed certs stay valid; a
// re-issue after the edit applies the new settings to the target agents.
func (s *Server) UpdateCertificate(id, root, credID, caID string, keyType domain.KeyType, enabled bool, targetAgents []string) error {
	root = normalizeDomain(root)
	if !validDomain(root) {
		return fmt.Errorf("invalid root domain %q", root)
	}
	return s.st.WithState(true, func(st *domain.State) error {
		cert := st.Certificates[id]
		if cert == nil {
			return errNotFound
		}
		if cert.IssueStatus == domain.StatusRunning {
			return errors.New("certificate is currently issuing, cannot edit")
		}
		if keyType == "" {
			keyType = st.Config.DefaultKeyType
		}
		if _, ok := st.CAs[caID]; !ok {
			return fmt.Errorf("acme ca %q not found", caID)
		}
		if _, ok := st.Credentials[credID]; !ok {
			return fmt.Errorf("cloudflare credential %q not found", credID)
		}
		cert.RootDomain = root
		cert.SanDomains = []string{root, "*." + root}
		cert.CredentialID = credID
		cert.ACMEID = caID
		cert.KeyType = keyType
		cert.Enabled = enabled
		cert.TargetAgents = append([]string(nil), targetAgents...)
		return nil
	})
}

// DeleteCertificate removes a certificate from state, cleans up its on-disk PEM
// blobs and drops any tasks that were created for it.
func (s *Server) DeleteCertificate(id string) error {
	if err := s.st.WithState(true, func(st *domain.State) error {
		cert := st.Certificates[id]
		if cert == nil {
			return errNotFound
		}
		if cert.IssueStatus == domain.StatusRunning {
			return errors.New("certificate is currently issuing, cannot delete")
		}
		delete(st.Certificates, id)
		for taskID, task := range st.Tasks {
			if task.CertID == id {
				delete(st.Tasks, taskID)
			}
		}
		return nil
	}); err != nil {
		return err
	}
	return s.st.RemoveCert(id)
}

const (
	taskTypeIssue = "issue"
	taskTypeRenew = "renew"
)

type issuePlan struct {
	TaskID       string
	TaskType     string
	CertID       string
	RootDomain   string
	SAN          []string
	Credential   domain.CloudflareCredential
	ACMEID       string
	DirectoryURL string
	AccountEmail string
	KeyType      domain.KeyType
	DNSSleepSecs int
}

// StartIssue atomically reserves an issue/renew task and runs it in the Server
// lifecycle, independent of the browser request that initiated it. A duplicate
// start is idempotent and returns the existing active task.
func (s *Server) StartIssue(certID, taskType string) (*domain.Task, bool, error) {
	if taskType != taskTypeIssue && taskType != taskTypeRenew {
		return nil, false, fmt.Errorf("unsupported issue task type %q", taskType)
	}
	plan, task, started, err := s.claimIssue(certID, taskType)
	if err != nil || !started {
		return task, started, err
	}
	if err := s.st.ResetCertificateLog(certID); err != nil {
		s.finishIssueFailure(plan, err)
		return task, false, err
	}
	s.issueLog(certID, "开始%s证书", map[bool]string{true: "自动续期", false: "签发"}[taskType == taskTypeRenew])
	s.issueLog(certID, "根域名: %s", plan.RootDomain)
	s.issueLog(certID, "SAN: %s", strings.Join(plan.SAN, ", "))
	s.issueLog(certID, "ACME CA: %s", plan.DirectoryURL)
	s.Go(func(parent context.Context) {
		ctx, cancel := context.WithTimeout(parent, 25*time.Minute)
		defer cancel()
		if err := s.runIssue(ctx, plan); err != nil {
			s.finishIssueFailure(plan, err)
			return
		}
		if plan.TaskType == taskTypeRenew {
			if err := s.DeployAll(ctx, plan.CertID); err != nil {
				s.log.Error("auto-deploy after renew failed", "cert_id", plan.CertID, "err", err)
			}
		}
	})
	return task, true, nil
}

func (s *Server) claimIssue(certID, taskType string) (issuePlan, *domain.Task, bool, error) {
	taskID, err := store.NewID()
	if err != nil {
		return issuePlan{}, nil, false, err
	}
	var plan issuePlan
	var result *domain.Task
	started := false
	err = s.st.WithState(true, func(st *domain.State) error {
		if st.Tasks == nil {
			st.Tasks = map[string]*domain.Task{}
		}
		cert := st.Certificates[certID]
		if cert == nil {
			return errNotFound
		}
		for _, active := range st.Tasks {
			if active.CertID == certID &&
				(active.Type == taskTypeIssue || active.Type == taskTypeRenew) &&
				(active.Status == domain.StatusPending || active.Status == domain.StatusRunning) {
				copy := *active
				result = &copy
				return nil
			}
		}
		ca := st.CAs[cert.ACMEID]
		cred := st.Credentials[cert.CredentialID]
		if ca == nil || !ca.Enabled {
			return fmt.Errorf("acme ca not enabled")
		}
		if cred == nil || !cred.Enabled {
			return fmt.Errorf("cloudflare credential not enabled")
		}
		now := time.Now()
		task := &domain.Task{
			ID: taskID, Type: taskType, CertID: certID,
			Status: domain.StatusRunning, CreatedAt: now, StartedAt: now,
		}
		st.Tasks[taskID] = task
		cert.IssueStatus = domain.StatusRunning
		cert.LastError = ""
		plan = issuePlan{
			TaskID: taskID, TaskType: taskType, CertID: certID,
			RootDomain: cert.RootDomain, SAN: append([]string(nil), cert.SanDomains...),
			Credential: *cred, ACMEID: cert.ACMEID, DirectoryURL: ca.DirectoryURL,
			AccountEmail: st.Config.ACMEAccountEmail, KeyType: cert.KeyType,
			DNSSleepSecs: st.Config.DNSSleepSeconds,
		}
		copy := *task
		result = &copy
		started = true
		return nil
	})
	return plan, result, started, err
}

func (s *Server) runIssue(ctx context.Context, plan issuePlan) error {
	issuer, err := s.issuerFor(plan.ACMEID, plan.DirectoryURL, plan.AccountEmail)
	if err != nil {
		return err
	}
	res, _, err := issuer.Issue(ctx, acme.IssueOptions{
		CertID: plan.CertID, RootDomain: plan.RootDomain, SAN: plan.SAN,
		Credential: plan.Credential, DirectoryURL: plan.DirectoryURL,
		AccountEmail: plan.AccountEmail, KeyType: plan.KeyType,
		DNSSleepSecs: plan.DNSSleepSecs,
		Logf: func(format string, args ...any) {
			s.issueLog(plan.CertID, format, args...)
		},
	})
	if err != nil {
		return fmt.Errorf("issue %s: %w", plan.RootDomain, err)
	}
	s.issueLog(plan.CertID, "正在保存证书文件")
	versionID, err := store.NewID()
	if err != nil {
		return err
	}
	v := domain.CertificateVersion{ID: versionID, IssuedAt: res.IssuedAt, ExpiresAt: res.ExpiresAt, Serial: res.Serial}
	v, err = s.st.WriteCertVersion(plan.CertID, v, res.CertPEM, res.CAPEM, res.FullchainPEM, res.PrivateKey)
	if err != nil {
		return err
	}
	var oldID string
	err = s.st.WithState(true, func(st *domain.State) error {
		cert := st.Certificates[plan.CertID]
		if cert == nil {
			return errNotFound
		}
		if cert.Current != nil {
			oldID = cert.Current.ID
		}
		cert.Current = &v
		cert.IssueStatus = domain.StatusSuccess
		cert.LastError = ""
		cert.Deploys = map[string]*domain.AgentDeployState{}
		if task := st.Tasks[plan.TaskID]; task != nil {
			task.Status = domain.StatusSuccess
			task.FinishedAt = time.Now()
			task.Error = ""
		}
		return nil
	})
	if err != nil {
		return err
	}
	if oldID != "" && oldID != versionID {
		_ = s.st.RemoveCertVersion(plan.CertID, oldID)
	}
	s.issueLog(plan.CertID, "证书签发成功")
	s.issueLog(plan.CertID, "证书到期时间: %s", res.ExpiresAt.Format(time.RFC3339))
	s.issueLog(plan.CertID, "签发任务完成")
	return nil
}

func (s *Server) finishIssueFailure(plan issuePlan, issueErr error) {
	message := issueErr.Error()
	s.issueLog(plan.CertID, "ERROR: %s", message)
	s.issueLog(plan.CertID, "签发任务失败")
	_ = s.st.WithState(true, func(st *domain.State) error {
		if cert := st.Certificates[plan.CertID]; cert != nil {
			cert.IssueStatus = domain.StatusFailed
			cert.LastError = message
		}
		if task := st.Tasks[plan.TaskID]; task != nil {
			task.Status = domain.StatusFailed
			task.FinishedAt = time.Now()
			task.Error = message
		}
		return nil
	})
	s.log.Error("certificate issue failed", "cert_id", plan.CertID, "err", issueErr)
}

func (s *Server) issueLog(certID, format string, args ...any) {
	message := fmt.Sprintf(format, args...)
	if err := s.st.AppendCertificateLog(certID, message); err != nil {
		s.log.Warn("append certificate log failed", "cert_id", certID, "err", err)
	}
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

// AgentVersions refreshes an Agent's live version/platform and returns stable
// upgrade targets that contain the matching Agent release asset.
func (s *Server) AgentVersions(ctx context.Context, agentID string) ([]string, error) {
	_ = s.RefreshAgent(ctx, agentID)
	agent := s.st.State().Agents[agentID]
	if agent == nil {
		return nil, errNotFound
	}
	if agent.GOOS == "" || agent.GOARCH == "" {
		return nil, fmt.Errorf("agent must be manually upgraded once before Web updates are available")
	}
	return updater.AvailableFor(ctx, updater.ComponentAgent, agent.Version, agent.GOOS, agent.GOARCH)
}

// StartAgentUpdate validates the selected target and updates the Agent in a
// lifecycle-bound background task. The wire request contains only Version.
func (s *Server) StartAgentUpdate(agentID, targetVersion string) error {
	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	versions, err := s.AgentVersions(ctx, agentID)
	cancel()
	if err != nil {
		return err
	}
	if !containsString(versions, targetVersion) {
		return fmt.Errorf("version %q is not an eligible agent upgrade", targetVersion)
	}
	if err := s.setAgentUpdateState(agentID, domain.StatusRunning, targetVersion, ""); err != nil {
		return err
	}
	s.Go(func(parent context.Context) {
		ctx, cancel := context.WithTimeout(parent, 5*time.Minute)
		defer cancel()
		if err := s.updateAgent(ctx, agentID, targetVersion); err != nil {
			_ = s.setAgentUpdateState(agentID, domain.StatusFailed, targetVersion, err.Error())
			s.log.Error("agent update failed", "agent_id", agentID, "target", targetVersion, "err", err)
		}
	})
	return nil
}

func (s *Server) updateAgent(ctx context.Context, agentID, targetVersion string) error {
	agent := s.st.State().Agents[agentID]
	if agent == nil {
		return errNotFound
	}
	u := fmt.Sprintf("https://%s:%d%s/update", agent.Address, agent.Port, protocol.AgentAPIPrefix)
	body, err := encodeJSON(protocol.UpdateRequest{Version: targetVersion})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 4 * time.Minute, Transport: &http.Transport{TLSClientConfig: s.cliTLSCfg}}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("send update signal: %w", err)
	}
	defer resp.Body.Close()
	var result protocol.UpdateResponse
	if err := decodeJSON(resp.Body, &result); err != nil {
		return err
	}
	if !result.Success {
		return fmt.Errorf("agent rejected update: %s", result.Error)
	}

	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
		if err := s.RefreshAgent(ctx, agentID); err != nil {
			continue
		}
		current := s.st.State().Agents[agentID]
		if current != nil && current.Version == targetVersion {
			return s.setAgentUpdateState(agentID, domain.StatusSuccess, targetVersion, "")
		}
	}
	return fmt.Errorf("agent did not restart on %s before timeout", targetVersion)
}

// RefreshAgent calls the fixed health endpoint and records the actual running
// version/platform reported by the Agent binary.
func (s *Server) RefreshAgent(ctx context.Context, agentID string) error {
	agent := s.st.State().Agents[agentID]
	if agent == nil {
		return errNotFound
	}
	u := fmt.Sprintf("https://%s:%d%s/health", agent.Address, agent.Port, protocol.AgentAPIPrefix)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: s.agentDialTimeout(), Transport: &http.Transport{TLSClientConfig: s.cliTLSCfg}}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var health protocol.HealthResponse
	if err := decodeJSON(resp.Body, &health); err != nil {
		return err
	}
	if health.AgentID != agentID {
		return fmt.Errorf("agent identity mismatch")
	}
	return s.st.WithState(true, func(st *domain.State) error {
		current := st.Agents[agentID]
		if current == nil {
			return errNotFound
		}
		current.Version = health.Version
		current.GOOS = health.GOOS
		current.GOARCH = health.GOARCH
		current.Status = domain.AgentRegistered
		current.LastSeenAt = time.Now()
		current.LastError = ""
		return nil
	})
}

func (s *Server) setAgentUpdateState(agentID string, status domain.OperationStatus, target, message string) error {
	return s.st.WithState(true, func(st *domain.State) error {
		agent := st.Agents[agentID]
		if agent == nil {
			return errNotFound
		}
		agent.UpdateStatus = status
		agent.UpdateTargetVersion = target
		agent.UpdateError = message
		return nil
	})
}

func containsString(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
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
