package server

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Flyinsky2004/oh-my-acme/internal/domain"
	"github.com/Flyinsky2004/oh-my-acme/internal/protocol"
	"github.com/Flyinsky2004/oh-my-acme/internal/store"
)

var (
	errRegisterTokenInvalid = errors.New("invalid or expired registration token")
	errRegisterTokenBound   = errors.New("token bound to a different agent")
	// errCertificateSelectionNotFound rejects a token whose selected
	// certificate does not exist (or was deleted) at mint time.
	errCertificateSelectionNotFound = errors.New("selected certificate not found")
)

// registerBeforeConsume is a test seam invoked after the CSR is signed and
// before the token is atomically consumed. It is nil in production; tests use
// it to hold concurrent registrations at a barrier.
var registerBeforeConsume func()

// ControlHandler returns the mTLS control-port HTTP handler used by agents to
// register and obtain their identity certificate.
func (s *Server) ControlHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+protocol.ControlAPIPrefix+"/register", s.handleRegister)
	return mux
}

// handleRegister processes an agent's one-time-token registration: it validates
// the token, derives the source IP from the TLS connection, signs the agent's
// CSR, persists the agent, marks the token used, and returns the identity.
//
// Token validation is repeated inside the store transaction: the pre-check is
// only a cheap rejection, while the locked re-check is authoritative. A
// concurrent replay, an expired token, a used token or a binding mismatch can
// therefore never consume the token twice or overwrite another winner's Agent
// record. If persistence fails, no certificate is returned.
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	// Registration is reachable before an Agent has a client certificate, so
	// bound the unauthenticated JSON/CSR body before token validation.
	r.Body = http.MaxBytesReader(w, r.Body, 256<<10)
	var req protocol.RegisterRequest
	if err := decodeJSON(r.Body, &req); err != nil {
		writeJSONErr(w, http.StatusBadRequest, "invalid request: "+err.Error())
		return
	}
	if req.Port < 0 || req.Port > 65535 {
		writeJSONErr(w, http.StatusBadRequest, "invalid agent port")
		return
	}
	name := strings.TrimSpace(req.Name)
	if len(name) > 255 {
		writeJSONErr(w, http.StatusBadRequest, "agent name is too long")
		return
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			writeJSONErr(w, http.StatusBadRequest, "agent name contains control characters")
			return
		}
	}

	st := s.st.State()
	rec, ok := st.Tokens[req.Token]
	if !ok || !tokenConsumableAt(rec, time.Now()) {
		writeJSONErr(w, http.StatusForbidden, errRegisterTokenInvalid.Error())
		return
	}
	if rec.AgentID != "" && req.AgentID != "" && req.AgentID != rec.AgentID {
		writeJSONErr(w, http.StatusForbidden, errRegisterTokenBound.Error())
		return
	}

	// The agent's source IP is the connection peer; the control port is not
	// behind a reverse proxy so RemoteAddr is authoritative.
	srcIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		writeJSONErr(w, http.StatusBadRequest, "cannot determine source address")
		return
	}
	ip := net.ParseIP(srcIP)
	if ip == nil {
		writeJSONErr(w, http.StatusBadRequest, "invalid source address")
		return
	}

	// Validate the CSR and sign it with the internal CA (IP SAN = source IP).
	if _, err := parseAgentCSR(req.CSR); err != nil {
		writeJSONErr(w, http.StatusBadRequest, err.Error())
		return
	}
	kp, err := s.ca.SignAgentCSR([]byte(req.CSR), []net.IP{ip})
	if err != nil {
		writeJSONErr(w, http.StatusInternalServerError, "sign agent cert: "+err.Error())
		return
	}
	agentCert, err := x509.ParseCertificate(pemBlock(kp.CertPEM))
	if err != nil {
		writeJSONErr(w, http.StatusInternalServerError, "parse signed cert")
		return
	}

	if registerBeforeConsume != nil {
		registerBeforeConsume()
	}

	var agentID string
	err = s.st.WithState(true, func(st *domain.State) error {
		now := time.Now()
		rec, ok := st.Tokens[req.Token]
		if !ok || !tokenConsumableAt(rec, now) {
			return errRegisterTokenInvalid
		}
		if rec.AgentID != "" && req.AgentID != "" && req.AgentID != rec.AgentID {
			return errRegisterTokenBound
		}
		agentID = rec.AgentID
		if agentID == "" {
			id, idErr := store.NewID()
			if idErr != nil {
				return idErr
			}
			agentID = id
		}
		agentName := name
		if agentName == "" {
			agentName = strings.TrimSpace(rec.AgentName)
		}
		if agentName == "" {
			agentName = "agent-" + shortID(agentID)
		}
		rec.UsedAt = now
		st.Agents[agentID] = &domain.Agent{
			ID: agentID, Name: agentName, Address: srcIP, Port: req.Port,
			Status: domain.AgentRegistered, Version: req.Version,
			GOOS: req.GOOS, GOARCH: req.GOARCH,
			RegisteredAt: now, CertExpiresAt: agentCert.NotAfter, LastSeenAt: now,
		}
		// Bind the new agent to the certificates selected when the token was
		// minted. A certificate deleted in the meantime is skipped so the
		// still-valid token can complete; existing targets and deploy records
		// are preserved and the binding is idempotent.
		for _, certID := range rec.CertificateIDs {
			cert := st.Certificates[certID]
			if cert == nil {
				continue
			}
			if !containsString(cert.TargetAgents, agentID) {
				cert.TargetAgents = append(cert.TargetAgents, agentID)
			}
		}
		return nil
	})
	if err != nil {
		switch {
		case errors.Is(err, errRegisterTokenInvalid):
			writeJSONErr(w, http.StatusForbidden, errRegisterTokenInvalid.Error())
		case errors.Is(err, errRegisterTokenBound):
			writeJSONErr(w, http.StatusForbidden, errRegisterTokenBound.Error())
		default:
			writeJSONErr(w, http.StatusInternalServerError, "persist agent: "+err.Error())
		}
		return
	}

	writeJSON(w, protocol.RegisterResponse{
		AgentID:     agentID,
		CertPEM:     string(kp.CertPEM),
		CAPEM:       string(s.ca.EncodeCA()),
		ServerCAPEM: string(s.ca.EncodeCA()),
		ExpiresAt:   agentCert.NotAfter.Format(time.RFC3339),
	})
	if s.log != nil {
		s.log.Info("agent registered", "agent_id", agentID, "addr", srcIP, "port", req.Port)
	}
}

// tokenConsumableAt reports whether a token is still unused and unexpired at
// the given time. The check is repeated under the store lock.
func tokenConsumableAt(rec *domain.TokenRecord, now time.Time) bool {
	if rec == nil || !rec.UsedAt.IsZero() {
		return false
	}
	if !rec.ExpiresAt.IsZero() && !now.Before(rec.ExpiresAt) {
		return false
	}
	return true
}

func parseAgentCSR(raw string) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode([]byte(raw))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("invalid CSR")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("invalid CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, errors.New("CSR signature invalid")
	}
	return csr, nil
}

// CreateAgentToken mints a one-time registration token for an agent with a
// given name. It keeps the legacy behaviour of selecting no certificates.
func (s *Server) CreateAgentToken(name string) (token string, agentID string, err error) {
	return s.CreateAgentTokenWithCertificates(name, nil)
}

// CreateAgentTokenWithCertificates mints a one-time registration token that
// also selects existing certificates. When the token is later consumed, the
// registered agent ID is appended to each selected certificate's TargetAgents.
//
// Selection is deduplicated and validated inside the same store transaction
// that writes the token, so an unknown certificate never leaves a partial
// token behind. An empty selection is valid and preserves the legacy
// behaviour. The binding only happens at registration time, so an unused or
// expired token never creates a dangling target.
func (s *Server) CreateAgentTokenWithCertificates(name string, certificateIDs []string) (token string, agentID string, err error) {
	agentID, err = store.NewID()
	if err != nil {
		return "", "", err
	}
	token, err = store.NewID()
	if err != nil {
		return "", "", err
	}
	selected := dedupeStrings(certificateIDs)
	err = s.st.WithState(true, func(st *domain.State) error {
		for _, certID := range selected {
			if st.Certificates[certID] == nil {
				return fmt.Errorf("%w: %s", errCertificateSelectionNotFound, certID)
			}
		}
		st.Tokens[token] = &domain.TokenRecord{
			Token:          token,
			AgentID:        agentID,
			AgentName:      name,
			CertificateIDs: selected,
			ExpiresAt:      time.Now().Add(10 * time.Minute),
		}
		return nil
	})
	if err != nil {
		return "", "", err
	}
	return token, agentID, nil
}

// DeleteAgent disables/removes an agent from the store.
func (s *Server) DeleteAgent(agentID string) {
	_ = s.st.WithState(true, func(st *domain.State) error {
		delete(st.Agents, agentID)
		for _, c := range st.Certificates {
			c.TargetAgents = removeString(c.TargetAgents, agentID)
			delete(c.Deploys, agentID)
		}
		return nil
	})
}

// --- small helpers ---

func pemBlock(b []byte) []byte {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil
	}
	return blk.Bytes
}

func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

func removeString(list []string, v string) []string {
	out := list[:0]
	for _, x := range list {
		if x != v {
			out = append(out, x)
		}
	}
	return out
}

// dedupeStrings removes duplicates while preserving first-seen order. It
// returns nil for an empty input so an unselected token stays JSON-identical
// to a legacy token.
func dedupeStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, v := range values {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}
