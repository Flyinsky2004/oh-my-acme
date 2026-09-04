// Package protocol defines the wire types exchanged between the oh-my-acme
// server and agent. The server connects to the agent over mTLS to push
// certificates; the agent connects to the server's control port to register
// and to renew internal identity certs.
package protocol

// API version prefix for all endpoints.
const (
	AgentAPIPrefix   = "/v1"
	ControlAPIPrefix = "/v1"
)

// ---- Agent registration (agent -> server control port) ----

// RegisterRequest is sent by the agent to the server's control port using the
// one-time token provided at install time. Address is the agent's
// self-reported listen port; the source IP is derived by the server from the
// TLS connection.
type RegisterRequest struct {
	Token   string `json:"token"`
	AgentID string `json:"agent_id"`
	Name    string `json:"name"`
	Port    int    `json:"port"`
	CSR     string `json:"csr"` // PEM PKCS#10 CSR; agent keeps its own private key
	Version string `json:"version"`
	GOOS    string `json:"goos"`
	GOARCH  string `json:"goarch"`
}

// RegisterResponse returns the CA-signed agent identity certificate chain and
// the CA certificate/fingerprint the agent should pin for the server.
type RegisterResponse struct {
	AgentID           string `json:"agent_id"`
	CertPEM           string `json:"cert_pem"`      // signed agent server cert
	CAPEM             string `json:"ca_pem"`        // issuing CA for the agent chain
	ServerCAPEM       string `json:"server_ca_pem"` // CA that signs the server's client cert
	ServerFingerprint string `json:"server_fingerprint"`
	ExpiresAt         string `json:"expires_at"`
}

// ---- Server -> Agent certificate push ----

// DeployRequest instructs the agent to install a certificate version.
// There is deliberately no command/args field: the agent only runs fixed,
// hard-coded nginx check + reload operations.
type DeployRequest struct {
	CertificateID string `json:"certificate_id"`
	RootDomain    string `json:"root_domain"`
	VersionID     string `json:"version_id"`
	CertPEM       string `json:"cert_pem"`
	CAPEM         string `json:"ca_pem"`
	FullchainPEM  string `json:"fullchain_pem"`
	PrivateKeyPEM string `json:"private_key_pem"`
}

// DeployResponse reports the installation result.
type DeployResponse struct {
	Success     bool   `json:"success"`
	AgentID     string `json:"agent_id"`
	NginxStatus string `json:"nginx_status"` // "not-found" | "ok" | "failed"
	Error       string `json:"error,omitempty"`
	Log         string `json:"log,omitempty"`
}

// ---- Agent binary update (server -> agent) ----

// UpdateRequest deliberately contains only a target version. The Agent builds
// repository URLs, asset names, executable paths and restart behavior itself.
type UpdateRequest struct {
	Version string `json:"version"`
}

// UpdateResponse reports whether the fixed-version update was accepted.
type UpdateResponse struct {
	Success        bool   `json:"success"`
	AgentID        string `json:"agent_id"`
	CurrentVersion string `json:"current_version"`
	TargetVersion  string `json:"target_version"`
	Restarting     bool   `json:"restarting"`
	Error          string `json:"error,omitempty"`
}

// ---- Agent health / status ----

// HealthRequest is a GET sent by the server to verify agent connectivity.
type HealthRequest struct{}

// HealthResponse reports basic agent facts.
type HealthResponse struct {
	AgentID          string `json:"agent_id"`
	Version          string `json:"version"`
	GOOS             string `json:"goos"`
	GOARCH           string `json:"goarch"`
	UptimeSeconds    int64  `json:"uptime_seconds"`
	NginxInstalled   bool   `json:"nginx_installed"`
	NginxConfigValid bool   `json:"nginx_config_valid"`
}
