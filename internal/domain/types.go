package domain

import (
	"time"
)

// KeyType is the cryptographic key algorithm for the certificate private key.
type KeyType string

const (
	KeyTypeEC256   KeyType = "ec-256"
	KeyTypeEC384   KeyType = "ec-384"
	KeyTypeRSA2048 KeyType = "rsa-2048"
	KeyTypeRSA4096 KeyType = "rsa-4096"
)

// OperationStatus describes a single asynchronous operation result.
type OperationStatus string

const (
	StatusPending OperationStatus = "pending"
	StatusRunning OperationStatus = "running"
	StatusSuccess OperationStatus = "success"
	StatusFailed  OperationStatus = "failed"
)

// AgentStatus reflects the registration/deployment readiness of an Agent.
type AgentStatus string

const (
	AgentUnregistered AgentStatus = "unregistered"
	AgentRegistered   AgentStatus = "registered"  // registered, control port reachable
	AgentUnreachable  AgentStatus = "unreachable" // registered but last connect failed
	AgentDisabled     AgentStatus = "disabled"
)

// SystemConfig holds the server-wide settings persisted in state.json.
type SystemConfig struct {
	WebListen                   string  `json:"web_listen"`
	WebPort                     int     `json:"web_port"`
	AgentControlListen          string  `json:"agent_control_listen"`
	AgentControlPort            int     `json:"agent_control_port"`
	DefaultACMEID               string  `json:"default_acme_id"`
	ACMEAccountEmail            string  `json:"acme_account_email"`
	DefaultKeyType              KeyType `json:"default_key_type"`
	RenewPreferenceDays         int     `json:"renew_preference_days"` // target days before expiry to renew
	RenewCheckInterval          string  `json:"renew_check_interval"`  // e.g. "24h"
	DNSSleepSeconds             int     `json:"dns_sleep_seconds"`     // 0 => automatic DNS propagation check
	MaxAgentDeployRetries       int     `json:"max_agent_deploy_retries"`
	ServerConnectTimeoutSeconds int     `json:"server_connect_timeout_seconds"`
	// ServerHost is the externally reachable host/IP used in generated Agent
	// install commands. Empty means auto-detect from local interfaces.
	ServerHost string `json:"server_host,omitempty"`
	// TelegramBot settings. TelegramEnabled defaults to false (disabled). The
	// token is stored like other secrets (plaintext in state.json, acme.sh
	// style); TelegramChatID (0 = unset) is the positive user ID of the single
	// private chat allowed to drive the bot. Group chats are never authorized.
	TelegramEnabled bool      `json:"telegram_enabled"`
	TelegramToken   string    `json:"telegram_token"`
	TelegramChatID  int64     `json:"telegram_chat_id"`
	CreatedAt       time.Time `json:"created_at"`
}

// ACMECA describes an ACME Certificate Authority endpoint.
type ACMECA struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	DirectoryURL string    `json:"directory_url"`
	Builtin      bool      `json:"builtin"`
	Enabled      bool      `json:"enabled"`
	CreatedAt    time.Time `json:"created_at"`
}

// CloudflareCredential holds the DNS provider credentials used for DNS-01.
// Token is stored in state.json; it is never written to logs or shown fully
// in the UI.
type CloudflareCredential struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Token     string    `json:"token"`
	ZoneID    string    `json:"zone_id"`
	AccountID string    `json:"account_id"`
	Enabled   bool      `json:"enabled"`
	Remark    string    `json:"remark,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// CertificateVersion is an immutable snapshot of a successfully issued
// certificate. The certificate and its private key live on disk as PEM files
// under the store's data directory (kept as plaintext, acme.sh style); the
// domain record only references the files by relative path. Never write the
// private key bytes into state.json or logs.
type CertificateVersion struct {
	ID            string    `json:"id"`
	IssuedAt      time.Time `json:"issued_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	Serial        string    `json:"serial"`
	CertFile      string    `json:"cert_file"` // relative to data dir
	CAFile        string    `json:"ca_file"`
	FullchainFile string    `json:"fullchain_file"`
	PrivkeyFile   string    `json:"privkey_file"`
}

// AgentDeployState records the last deployment result for a single Agent.
type AgentDeployState struct {
	AgentID       string          `json:"agent_id"`
	VersionID     string          `json:"version_id"`
	Status        OperationStatus `json:"status"`
	LastAttemptAt time.Time       `json:"last_attempt_at"`
	LastSuccessAt time.Time       `json:"last_success_at,omitempty"`
	Error         string          `json:"error,omitempty"`
	RetryCount    int             `json:"retry_count"`
}

// Certificate is the top-level aggregate: configuration plus the current
// issued version plus per-Agent deployment state.
type Certificate struct {
	ID           string                       `json:"id"`
	RootDomain   string                       `json:"root_domain"`
	SanDomains   []string                     `json:"san_domains"`
	CredentialID string                       `json:"credential_id"`
	ACMEID       string                       `json:"acme_id"`
	KeyType      KeyType                      `json:"key_type"`
	Enabled      bool                         `json:"enabled"`
	TargetAgents []string                     `json:"target_agents"`
	Current      *CertificateVersion          `json:"current,omitempty"`
	Deploys      map[string]*AgentDeployState `json:"deploys,omitempty"`
	IssueStatus  OperationStatus              `json:"issue_status"`
	LastError    string                       `json:"last_error,omitempty"`
	CreatedAt    time.Time                    `json:"created_at"`
}

// Agent is a target machine that receives certificates.
type Agent struct {
	ID                  string          `json:"id"`
	Name                string          `json:"name"`
	Address             string          `json:"address"` // IP/hostname reachable by the server for mTLS push
	Port                int             `json:"port"`    // agent listen port
	Status              AgentStatus     `json:"status"`
	Version             string          `json:"version,omitempty"`
	GOOS                string          `json:"goos,omitempty"`
	GOARCH              string          `json:"goarch,omitempty"`
	UpdateStatus        OperationStatus `json:"update_status,omitempty"`
	UpdateTargetVersion string          `json:"update_target_version,omitempty"`
	UpdateError         string          `json:"update_error,omitempty"`
	RegisteredAt        time.Time       `json:"registered_at"`
	CertExpiresAt       time.Time       `json:"cert_expires_at,omitempty"`
	LastError           string          `json:"last_error,omitempty"`
	LastSeenAt          time.Time       `json:"last_seen_at,omitempty"`
}

// TokenRecord is a one-time registration token.
type TokenRecord struct {
	Token     string    `json:"token"`
	AgentID   string    `json:"agent_id"`
	AgentName string    `json:"agent_name"`
	ExpiresAt time.Time `json:"expires_at"`
	UsedAt    time.Time `json:"used_at,omitempty"`
}

// TokenConsumable reports whether the token is still valid for a registration.
func (t *TokenRecord) TokenConsumable() bool {
	if t == nil || t.UsedAt.IsZero() == false {
		return false
	}
	if !t.ExpiresAt.IsZero() && time.Now().After(t.ExpiresAt) {
		return false
	}
	return true
}

// Task is a persisted unit of work (issue, renew, deploy).
type Task struct {
	ID         string          `json:"id"`
	Type       string          `json:"type"` // issue | renew | deploy
	CertID     string          `json:"cert_id"`
	AgentID    string          `json:"agent_id,omitempty"`
	Status     OperationStatus `json:"status"`
	CreatedAt  time.Time       `json:"created_at"`
	StartedAt  time.Time       `json:"started_at,omitempty"`
	FinishedAt time.Time       `json:"finished_at,omitempty"`
	Error      string          `json:"error,omitempty"`
	NextRunAt  time.Time       `json:"next_run_at,omitempty"`
}

// AdminAccount holds the single administrator's credentials and first-run
// setup token. The password is stored as an Argon2id hash; the setup token is
// one of the ways to initialise the password on first boot and the password is
// never persisted in plaintext.
type AdminAccount struct {
	Username            string    `json:"username"`
	PasswordHash        string    `json:"password_hash"`
	SetupToken          string    `json:"setup_token,omitempty"`
	SetupTokenExpiresAt time.Time `json:"setup_token_expires_at,omitempty"`
	SetupTokenUsed      bool      `json:"setup_token_used"`
	CreatedAt           time.Time `json:"created_at"`
}

// State is the full persisted application state. It is the single source of
// truth loaded from and written to state.json.
type State struct {
	Version      int                              `json:"version"`
	Config       SystemConfig                     `json:"config"`
	Admin        AdminAccount                     `json:"admin"`
	CAs          map[string]*ACMECA               `json:"cas"`
	Credentials  map[string]*CloudflareCredential `json:"credentials"`
	Certificates map[string]*Certificate          `json:"certificates"`
	Agents       map[string]*Agent                `json:"agents"`
	Tokens       map[string]*TokenRecord          `json:"tokens"`
	Tasks        map[string]*Task                 `json:"tasks"`
}
