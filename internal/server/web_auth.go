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
	csrf          string
	pendingSecret string
	pendingUntil  time.Time
	id            string
	username      string
	expiresAt     time.Time
}

// sessionStore is an in-memory map of active admin sessions. now is injectable
// so tests can advance time without sleeping. generation advances whenever all
// sessions are revoked or rotated, letting an in-flight login detect that a
// security state change happened while it was verifying credentials.
type sessionStore struct {
	now        func() time.Time
	mu         sync.Mutex
	sessions   map[string]session
	ttl        time.Duration
	generation uint64
}

func newSessionStore() *sessionStore {
	return &sessionStore{sessions: map[string]session{}, ttl: 24 * time.Hour, now: time.Now}
}

func (ss *sessionStore) nowTime() time.Time {
	if ss.now != nil {
		return ss.now()
	}
	return time.Now()
}

func (ss *sessionStore) create(username string) (id string) {
	id = randomHex(24)
	ss.mu.Lock()
	defer ss.mu.Unlock()
	ss.sessions[id] = session{csrf: randomHex(24), id: id, username: username, expiresAt: ss.nowTime().Add(ss.ttl)}
	return id
}

// rotate atomically replaces every session with a single fresh one. Doing the
// revoke+create under one lock closes the window where a concurrent request
// could create a session that the rotation then silently drops, and keeps the
// replacement CSRF token in sync with the rotated cookie.
func (ss *sessionStore) rotate(username string) session {
	replacement := session{
		csrf: randomHex(24), id: randomHex(24), username: username,
		expiresAt: ss.nowTime().Add(ss.ttl),
	}
	ss.mu.Lock()
	defer ss.mu.Unlock()
	ss.sessions = map[string]session{replacement.id: replacement}
	ss.generation++
	return replacement
}

// currentGeneration reports the revocation/rotation epoch.
func (ss *sessionStore) currentGeneration() uint64 {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	return ss.generation
}

// count reports the number of live sessions (used by regression tests).
func (ss *sessionStore) count() int {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	return len(ss.sessions)
}

func (ss *sessionStore) valid(id string) bool {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	s, ok := ss.sessions[id]
	if !ok || ss.nowTime().After(s.expiresAt) {
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

var errSetupTokenInvalid = errors.New("初始化令牌无效或已过期，请重启 Server 生成新令牌")

func validateAdminCredentials(username, password string) (string, error) {
	username = strings.TrimSpace(username)
	if username == "" || len(username) > 64 {
		return "", errors.New("username must be 1-64 characters")
	}
	if len(password) < 8 {
		return "", errors.New("password must be at least 8 characters")
	}
	return username, nil
}

// setAdminPassword stores the username + Argon2id password hash. It is used by
// tests and by callers that already own the setup transition; the public
// bootstrap path goes through setupAdmin so the token check and commit share
// one store lock.
func (s *Server) setAdminPassword(username, password string) error {
	username, err := validateAdminCredentials(username, password)
	if err != nil {
		return err
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

// setupAdmin validates the one-time bootstrap token and commits the first
// administrator in the same WithState critical section. A concurrent second
// submission therefore loses the race instead of overwriting the winner, and a
// failed disk write leaves the token usable for a retry.
func (s *Server) setupAdmin(username, password, token string) error {
	username, err := validateAdminCredentials(username, password)
	if err != nil {
		return err
	}
	hash, err := hashPassword(password)
	if err != nil {
		return err
	}
	return s.setupAdminWithHash(username, hash, token)
}

// setupAdminWithHash commits an already-hashed administrator inside one store
// transaction. The web handler hashes under the password work gate so a flood
// of bootstrap attempts cannot allocate unbounded Argon2 memory.
func (s *Server) setupAdminWithHash(username, hash, token string) error {
	username = strings.TrimSpace(username)
	return s.st.Update(func(st *domain.State) error {
		admin := &st.Admin
		if admin.SetupTokenUsed || admin.SetupToken == "" ||
			!time.Now().Before(admin.SetupTokenExpiresAt) ||
			subtle.ConstantTimeCompare([]byte(admin.SetupToken), []byte(token)) != 1 {
			return errSetupTokenInvalid
		}
		admin.Username = username
		admin.PasswordHash = hash
		admin.SetupToken = ""
		admin.SetupTokenExpiresAt = time.Time{}
		admin.SetupTokenUsed = true
		admin.CreatedAt = time.Now()
		return nil
	})
}

// InitialSetupToken returns (generating if needed) the one-time setup token
// printed at first start. Tokens expire after 10 minutes; restarting the
// uninitialised server generates a replacement for an expired token. The
// read-or-generate decision and the write share one store lock so concurrent
// callers observe a single token.
func (s *Server) InitialSetupToken() (string, error) {
	var token string
	err := s.st.Update(func(st *domain.State) error {
		admin := &st.Admin
		if admin.SetupTokenUsed {
			token = ""
			return nil
		}
		if admin.SetupToken != "" && time.Now().Before(admin.SetupTokenExpiresAt) {
			token = admin.SetupToken
			return nil
		}
		token = randomHex(24)
		admin.SetupToken = token
		admin.SetupTokenExpiresAt = time.Now().Add(10 * time.Minute)
		return nil
	})
	if err != nil {
		return "", err
	}
	return token, nil
}

func (ss *sessionStore) get(id string) (session, bool) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	s, ok := ss.sessions[id]
	return s, ok && ss.nowTime().Before(s.expiresAt)
}

func (ss *sessionStore) setPending(id, secret string) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	s, ok := ss.sessions[id]
	if ok {
		s.pendingSecret = secret
		s.pendingUntil = ss.nowTime().Add(10 * time.Minute)
		ss.sessions[id] = s
	}
}

func (ss *sessionStore) revokeAll() {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	ss.sessions = map[string]session{}
	ss.generation++
}
