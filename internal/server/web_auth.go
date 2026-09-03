package server

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Flyinsky2004/oh-my-acme/internal/domain"
	"golang.org/x/crypto/argon2"
)

// --- Argon2id password hashing ---

const (
	argonTime    = 1
	argonMemory  = 64 * 1024
	argonThreads = 4
	argonKeyLen  = 32
	argonSaltLen = 16
)

// hashPassword returns an Argon2id hash stored as $argon2id$v=19$params$salt$hash.
func hashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	params := fmt.Sprintf("m=%d,t=%d,p=%d", argonMemory, argonTime, argonThreads)
	return "$argon2id$v=19$" + params + "$" +
		base64.RawStdEncoding.EncodeToString(salt) + "$" +
		base64.RawStdEncoding.EncodeToString(key), nil
}

func verifyPassword(password, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}
	key := argon2.IDKey([]byte(password), salt, t, m, p, uint32(len(expected)))
	return subtle.ConstantTimeCompare(key, expected) == 1
}

// --- Sessions ---

type session struct {
	id        string
	username  string
	expiresAt time.Time
}

// sessionStore is an in-memory map of active admin sessions.
type sessionStore struct {
	mu       sync.Mutex
	sessions map[string]session
	ttl      time.Duration
}

func newSessionStore() *sessionStore {
	return &sessionStore{sessions: map[string]session{}, ttl: 24 * time.Hour}
}

func (ss *sessionStore) create(username string) (id string) {
	id = randomHex(24)
	ss.mu.Lock()
	defer ss.mu.Unlock()
	ss.sessions[id] = session{id: id, username: username, expiresAt: time.Now().Add(ss.ttl)}
	return id
}

func (ss *sessionStore) valid(id string) bool {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	s, ok := ss.sessions[id]
	if !ok || time.Now().After(s.expiresAt) {
		delete(ss.sessions, id)
		return false
	}
	return true
}

func (ss *sessionStore) delete(id string) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	delete(ss.sessions, id)
}

// --- helpers ---

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

// getAdmin returns the stored admin account.
func (s *Server) getAdmin() domain.AdminAccount { return s.st.State().Admin }

// setAdminPassword stores the username + Argon2id password hash.
func (s *Server) setAdminPassword(username, password string) error {
	username = strings.TrimSpace(username)
	if username == "" || len(username) > 64 {
		return errors.New("username must be 1-64 characters")
	}
	if len(password) < 8 {
		return errors.New("password must be at least 8 characters")
	}
	hash, err := hashPassword(password)
	if err != nil {
		return err
	}
	return s.st.WithState(true, func(st *domain.State) error {
		st.Admin.Username = username
		st.Admin.PasswordHash = hash
		st.Admin.SetupToken = ""
		st.Admin.SetupTokenExpiresAt = time.Time{}
		st.Admin.SetupTokenUsed = true
		st.Admin.CreatedAt = time.Now()
		return nil
	})
}

// InitialSetupToken returns (generating if needed) the one-time setup token
// printed at first start. Tokens expire after 10 minutes; restarting the
// uninitialised server generates a replacement for an expired token.
func (s *Server) InitialSetupToken() (string, error) {
	admin := s.st.State().Admin
	if admin.SetupTokenUsed {
		return "", nil
	}
	if admin.SetupToken != "" && time.Now().Before(admin.SetupTokenExpiresAt) {
		return admin.SetupToken, nil
	}
	token := randomHex(24)
	expiresAt := time.Now().Add(10 * time.Minute)
	err := s.st.WithState(true, func(st *domain.State) error {
		st.Admin.SetupToken = token
		st.Admin.SetupTokenExpiresAt = expiresAt
		return nil
	})
	if err != nil {
		return "", err
	}
	return token, nil
}
