// Package agent is the on-machine certificate deployment agent. It exposes a
// small mTLS HTTP API through which the server pushes certificate versions.
// The agent writes PEM files into a fixed directory and, if nginx is present
// and already configured to reference those paths, runs a validation +
// reload. It executes no arbitrary commands: the only programs ever launched
// are a hard-coded nginx "-t" and "systemctl reload nginx".
package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// LoadConfig reads and parses config.json.
func LoadConfig(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var cfg Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	return cfg, nil
}

// SaveConfig atomically writes config.json. The registration token is cleared
// once registration succeeds.
func SaveConfig(path string, cfg Config) error {
	b, err := json.MarshalIndent(&cfg, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// FillDefaults derives unset identity/cert paths from the binary's directory.
// install.sh writes a minimal config.json; the identity files live next to the
// binary (e.g. /opt/oh-my-acme-agent/agent.crt) and are produced at
// registration time.
func (c *Config) FillDefaults() {
	dir := filepath.Dir(mustExePath())
	if c.CertFile == "" {
		c.CertFile = filepath.Join(dir, "agent.crt")
	}
	if c.KeyFile == "" {
		c.KeyFile = filepath.Join(dir, "agent.key")
	}
	if c.ServerCAFile == "" {
		c.ServerCAFile = filepath.Join(dir, "ca.crt")
	}
	if c.CAFile == "" {
		c.CAFile = filepath.Join(dir, "ca.crt")
	}
	if c.CertDir == "" {
		c.CertDir = filepath.Join(dir, "certs")
	}
	if c.LogDir == "" {
		c.LogDir = filepath.Join(dir, "logs")
	}
}

func mustExePath() string {
	p, err := os.Executable()
	if err != nil {
		return "."
	}
	return p
}

// Config is the agent's persisted configuration (config.json), written by
// install.sh. Sensitive fields are kept in-memory only; the registration token
// is cleared from the file after a successful registration.
type Config struct {
	Listen    string `json:"listen"`
	Port      int    `json:"port"`
	CertDir   string `json:"cert_dir"` // /opt/oh-my-acme-agent/certs
	LogDir    string `json:"log_dir"`
	ServerURL string `json:"server_url"` // https://server:9444
	AgentID   string `json:"agent_id,omitempty"`
	Name      string `json:"name,omitempty"`

	// Identity material for mTLS (agent presents its own server identity; it
	// verifies the server's client cert against ServerCAFile).
	CAFile       string `json:"ca_file"`        // issuing CA for agent chain (also trust anchor)
	CertFile     string `json:"cert_file"`      // agent server identity
	KeyFile      string `json:"key_file"`       // agent private key
	ServerCAFile string `json:"server_ca_file"` // CA that signs the server's client cert

	// Registration token (cleared after registration).
	Token         string `json:"token,omitempty"`
	CAFingerprint string `json:"ca_fingerprint,omitempty"`

	// Hard-coded executable paths; resolved once at startup from a whitelist.
	NginxPath     string `json:"nginx_path,omitempty"`
	SystemctlPath string `json:"systemctl_path,omitempty"`

	CreatedAt time.Time `json:"created_at"`
}
