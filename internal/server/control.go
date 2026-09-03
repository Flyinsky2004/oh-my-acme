package server

import (
	"crypto/x509"
	"encoding/pem"
	"net"
	"net/http"
	"time"

	"github.com/Flyinsky2004/oh-my-acme/internal/domain"
	"github.com/Flyinsky2004/oh-my-acme/internal/protocol"
	"github.com/Flyinsky2004/oh-my-acme/internal/store"
)

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
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	// Registration is reachable before an Agent has a client certificate, so
	// bound the unauthenticated JSON/CSR body before token validation.
	r.Body = http.MaxBytesReader(w, r.Body, 256<<10)
	var req protocol.RegisterRequest
	if err := decodeJSON(r.Body, &req); err != nil {
		writeJSONErr(w, http.StatusBadRequest, "invalid request: "+err.Error())
		return
	}

	st := s.st.State()
	rec, ok := st.Tokens[req.Token]
	if !ok || !rec.TokenConsumable() {
		writeJSONErr(w, http.StatusForbidden, "invalid or expired registration token")
		return
	}
	if rec.AgentID != "" && req.AgentID != "" && req.AgentID != rec.AgentID {
		writeJSONErr(w, http.StatusForbidden, "token bound to a different agent")
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
	block, _ := pem.Decode([]byte(req.CSR))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		writeJSONErr(w, http.StatusBadRequest, "invalid CSR")
		return
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		writeJSONErr(w, http.StatusBadRequest, "invalid CSR: "+err.Error())
		return
	}
	if err := csr.CheckSignature(); err != nil {
		writeJSONErr(w, http.StatusBadRequest, "CSR signature invalid")
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

	agentID := rec.AgentID
	if agentID == "" {
		agentID, err = store.NewID()
		if err != nil {
			writeJSONErr(w, http.StatusInternalServerError, "generate id")
			return
		}
	}
	name := req.Name
	if name == "" {
		name = "agent-" + shortID(agentID)
	}

	err = s.st.WithState(true, func(st *domain.State) error {
		if t, ok := st.Tokens[req.Token]; ok {
			t.UsedAt = time.Now()
		}
		st.Agents[agentID] = &domain.Agent{
			ID:            agentID,
			Name:          name,
			Address:       srcIP,
			Port:          req.Port,
			Status:        domain.AgentRegistered,
			Version:       req.Version,
			RegisteredAt:  time.Now(),
			CertExpiresAt: agentCert.NotAfter,
			LastSeenAt:    time.Now(),
		}
		return nil
	})
	if err != nil {
		writeJSONErr(w, http.StatusInternalServerError, "persist agent: "+err.Error())
		return
	}

	writeJSON(w, protocol.RegisterResponse{
		AgentID:     agentID,
		CertPEM:     string(kp.CertPEM),
		CAPEM:       string(s.ca.EncodeCA()),
		ServerCAPEM: string(s.ca.EncodeCA()),
		ExpiresAt:   agentCert.NotAfter.Format(time.RFC3339),
	})
	s.log.Info("agent registered", "agent_id", agentID, "addr", srcIP, "port", req.Port)
}

// CreateAgentToken mints a one-time registration token for an agent with a
// given name. It returns the token, the agent ID and an install command hint.
func (s *Server) CreateAgentToken(name string) (token string, agentID string, err error) {
	agentID, err = store.NewID()
	if err != nil {
		return "", "", err
	}
	token, err = store.NewID()
	if err != nil {
		return "", "", err
	}
	err = s.st.WithState(true, func(st *domain.State) error {
		st.Tokens[token] = &domain.TokenRecord{
			Token:     token,
			AgentID:   agentID,
			AgentName: name,
			ExpiresAt: time.Now().Add(10 * time.Minute),
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
