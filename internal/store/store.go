// Package store persists the oh-my-acme server state. State is a single JSON
// document (state.json) authoritative for configuration, credentials, agents,
// tokens and tasks. Certificate PEM blobs — including plaintext private keys,
// kept exactly like acme.sh — are stored as files under a data directory and
// referenced from state.json by relative path. Writes are serialized and
// applied atomically (temp file + fsync + rename) with a backup of the previous
// good state so a torn file never corrupts the store.
package store

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Flyinsky2004/oh-my-acme/internal/domain"
)

const stateVersion = 1

// Store owns the data directory and the in-memory state. A single mutex
// serializes all state mutations; the current state is swapped in one write.
type Store struct {
	dataDir string
	mu      sync.Mutex
	state   domain.State
}

// loadDefaults returns a fresh State with sensible defaults.
func loadDefaults(dataDir string) domain.State {
	return domain.State{
		Version: stateVersion,
		Config: domain.SystemConfig{
			WebListen:                   "127.0.0.1",
			WebPort:                     8080,
			AgentControlListen:          "0.0.0.0",
			AgentControlPort:            9444,
			DefaultKeyType:              domain.KeyTypeEC256,
			RenewPreferenceDays:         30,
			RenewCheckInterval:          "24h",
			DNSSleepSeconds:             0,
			MaxAgentDeployRetries:       3,
			ServerConnectTimeoutSeconds: 10,
			CreatedAt:                   time.Now(),
		},
		CAs:          map[string]*domain.ACMECA{},
		Credentials:  map[string]*domain.CloudflareCredential{},
		Certificates: map[string]*domain.Certificate{},
		Agents:       map[string]*domain.Agent{},
		Tokens:       map[string]*domain.TokenRecord{},
		Tasks:        map[string]*domain.Task{},
	}
}

// Open loads (or initialises) the store rooted at dataDir. All runtime data,
// including the state file and cert blobs, lives under dataDir.
func Open(dataDir string) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}
	s := &Store{dataDir: dataDir}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) StatePath() string { return filepath.Join(s.dataDir, "state.json") }

func (s *Store) load() error {
	path := s.StatePath()
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			s.state = loadDefaults(s.dataDir)
			return nil
		}
		return fmt.Errorf("read state: %w", err)
	}
	var st domain.State
	if err := json.Unmarshal(b, &st); err != nil {
		// Fall back to the backup if the primary file is corrupt.
		backup := path + ".backup"
		if bb, berr := os.ReadFile(backup); berr == nil {
			if json.Unmarshal(bb, &st) == nil {
				s.state = st
				return nil
			}
		}
		return fmt.Errorf("parse state (and backup): %w", err)
	}
	if st.Version != stateVersion {
		return fmt.Errorf("unsupported state version %d (want %d)", st.Version, stateVersion)
	}
	s.state = st
	return nil
}

// State returns a deep snapshot of the current state. The application is
// small and file-backed, so a JSON round trip is preferable to exposing map or
// pointer aliases that could race with background issuance and HTMX polling.
func (s *Store) State() domain.State {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := json.Marshal(&s.state)
	if err != nil {
		panic(fmt.Sprintf("clone state: %v", err))
	}
	var snapshot domain.State
	if err := json.Unmarshal(data, &snapshot); err != nil {
		panic(fmt.Sprintf("clone state: %v", err))
	}
	return snapshot
}

// Save writes the current state to disk atomically. Callers that mutate state
// should mutate s.state directly under the lock; this method assumes the caller
// holds s.mu (see the WithState helper).
func (s *Store) Save() error {
	return s.saveLocked()
}

// WithState provides exclusive access to the in-memory state. The callback may
// mutate s.state; if commit is true the state is persisted afterwards. Any
// error from the callback aborts the save.
func (s *Store) WithState(commit bool, fn func(*domain.State) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := fn(&s.state); err != nil {
		return err
	}
	if commit {
		return s.saveLocked()
	}
	return nil
}

func (s *Store) saveLocked() error {
	path := s.StatePath()
	tmp := path + ".tmp"
	b, err := json.MarshalIndent(&s.state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}
	if err := writeFileSync(tmp, b, 0o600); err != nil {
		return err
	}
	// Keep the current file as a backup before replacing it.
	if old, err := os.ReadFile(path); err == nil && len(old) > 0 {
		if err := writeFileSync(path+".backup", old, 0o600); err != nil {
			return err
		}
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("rename state: %w", err)
	}
	return nil
}

// --- Certificate PEM blob management ---

func (s *Store) certDir(certID, versionID string) string {
	return filepath.Join(s.dataDir, "certs", certID, versionID)
}

// WriteCertVersion writes the four PEM files for a certificate version and
// returns the relative paths stored in state.json. VersionID and certID must
// be validated (no path separators) by callers.
func (s *Store) WriteCertVersion(certID string, v domain.CertificateVersion, cert, ca, fullchain, privkey []byte) (domain.CertificateVersion, error) {
	dir := s.certDir(certID, v.ID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return v, err
	}
	write := func(name string, data []byte, mode os.FileMode) error {
		p := filepath.Join(dir, name)
		if err := writeFileSync(p, data, mode); err != nil {
			return err
		}
		return os.Chmod(p, mode)
	}
	rel := func(name string) string { return filepath.Join("certs", certID, v.ID, name) }
	if err := write("cert.pem", cert, 0o644); err != nil {
		return v, err
	}
	if err := write("ca.pem", ca, 0o644); err != nil {
		return v, err
	}
	if err := write("fullchain.pem", fullchain, 0o644); err != nil {
		return v, err
	}
	if err := write("privkey.pem", privkey, 0o600); err != nil {
		return v, err
	}
	v.CertFile = rel("cert.pem")
	v.CAFile = rel("ca.pem")
	v.FullchainFile = rel("fullchain.pem")
	v.PrivkeyFile = rel("privkey.pem")
	return v, nil
}

// ResetCertificateLog truncates the per-certificate latest issuance log.
func (s *Store) ResetCertificateLog(certID string) error {
	if err := validateID(certID); err != nil {
		return err
	}
	dir := filepath.Join(s.dataDir, "certs", certID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return writeFileSync(filepath.Join(dir, "latest.log"), nil, 0o600)
}

// AppendCertificateLog appends one timestamped line to the latest issuance log.
func (s *Store) AppendCertificateLog(certID, message string) error {
	if err := validateID(certID); err != nil {
		return err
	}
	dir := filepath.Join(s.dataDir, "certs", certID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	path := filepath.Join(dir, "latest.log")
	line := fmt.Sprintf("[%s] %s\n", time.Now().Format("15:04:05"), message)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.WriteString(line); err != nil {
		return err
	}
	return file.Sync()
}

// ReadCertificateLog returns the most recent issuance log for a certificate.
func (s *Store) ReadCertificateLog(certID string) (string, error) {
	if err := validateID(certID); err != nil {
		return "", err
	}
	data, err := os.ReadFile(filepath.Join(s.dataDir, "certs", certID, "latest.log"))
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func (s *Store) agentDeployLogPath(certID, agentID string) (string, error) {
	if err := validateID(certID); err != nil {
		return "", err
	}
	if err := validateID(agentID); err != nil {
		return "", err
	}
	return filepath.Join(s.dataDir, "certs", certID, "deploys", agentID+".log"), nil
}

// WriteAgentDeployLog replaces the last deploy log for one certificate+agent.
func (s *Store) WriteAgentDeployLog(certID, agentID, text string) error {
	path, err := s.agentDeployLogPath(certID, agentID)
	if err != nil {
		return err
	}
	return writeFileSync(path, []byte(text), 0o600)
}

// ReadAgentDeployLog returns the last deploy log for one certificate+agent.
func (s *Store) ReadAgentDeployLog(certID, agentID string) (string, error) {
	path, err := s.agentDeployLogPath(certID, agentID)
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// RemoveCertVersion deletes the on-disk certificate version directory.
func (s *Store) RemoveCertVersion(certID, versionID string) error {
	if err := validateID(versionID); err != nil {
		return err
	}
	return os.RemoveAll(s.certDir(certID, versionID))
}

// RemoveCert deletes the whole on-disk directory for a certificate — all issued
// version blobs and the issuance log. Callers should have already removed the
// certificate from state; this cleans up its PEM files.
func (s *Store) RemoveCert(certID string) error {
	if err := validateID(certID); err != nil {
		return err
	}
	return os.RemoveAll(filepath.Join(s.dataDir, "certs", certID))
}

// ReadCertPEM loads the cert/ca/fullchain/privkey bytes for a version. First
// return is cert, then ca, fullchain, privkey.
func (s *Store) ReadCertVersion(v domain.CertificateVersion) (cert, ca, fullchain, privkey []byte, err error) {
	cert, err = os.ReadFile(filepath.Join(s.dataDir, v.CertFile))
	if err != nil {
		return
	}
	ca, err = os.ReadFile(filepath.Join(s.dataDir, v.CAFile))
	if err != nil {
		return
	}
	fullchain, err = os.ReadFile(filepath.Join(s.dataDir, v.FullchainFile))
	if err != nil {
		return
	}
	privkey, err = os.ReadFile(filepath.Join(s.dataDir, v.PrivkeyFile))
	return
}

// --- Generic files for keys / account keys ---

func (s *Store) filePath(rel string) string { return filepath.Join(s.dataDir, rel) }

// WriteSecretFile writes a private-key-style file (e.g. an ACME account key)
// under the data dir with 0600.
func (s *Store) WriteSecretFile(rel string, data []byte) error {
	p := s.filePath(rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	return writeFileSync(p, data, 0o600)
}

// ReadFile reads a file under the data dir.
func (s *Store) ReadFile(rel string) ([]byte, error) {
	return os.ReadFile(s.filePath(rel))
}

// writeFileSync writes bytes with fsync to guarantee durability before any
// rename that exposes the file.
func writeFileSync(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	return f.Chmod(mode)
}

// NewID returns a random 16-byte hex id.
func NewID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// validateID rejects id strings containing path separators or traversal.
func validateID(id string) error {
	if id == "" || id != filepath.Base(id) || id == "." || id == ".." {
		return fmt.Errorf("invalid id %q", id)
	}
	return nil
}
