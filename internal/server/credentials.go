package server

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Flyinsky2004/oh-my-acme/internal/domain"
	"github.com/Flyinsky2004/oh-my-acme/internal/store"
)

// CreateCredential stores a Cloudflare credential.
func (s *Server) CreateCredential(name, token, zoneID, accountID, remark string) (string, error) {
	if strings.TrimSpace(token) == "" {
		return "", errors.New("cf token is required")
	}
	id, err := store.NewID()
	if err != nil {
		return "", err
	}
	err = s.st.WithState(true, func(st *domain.State) error {
		st.Credentials[id] = &domain.CloudflareCredential{
			ID:        id,
			Name:      strings.TrimSpace(name),
			Token:     token,
			ZoneID:    zoneID,
			AccountID: accountID,
			Remark:    remark,
			Enabled:   true,
			CreatedAt: time.Now(),
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return id, nil
}

// UpdateCredential updates non-token fields; if newToken is non-empty it is
// also replaced. It returns an error if the credential is referenced by a
// certificate and is being disabled/deleted.
func (s *Server) UpdateCredential(id, name, token, zoneID, accountID, remark string, enabled bool) error {
	return s.st.WithState(true, func(st *domain.State) error {
		c, ok := st.Credentials[id]
		if !ok {
			return errNotFound
		}
		refs := credentialRefCount(st, id)
		if !enabled && refs > 0 {
			return fmt.Errorf("credential is used by %d certificate(s); disable those first", refs)
		}
		c.Name = strings.TrimSpace(name)
		c.ZoneID = zoneID
		c.AccountID = accountID
		c.Remark = remark
		c.Enabled = enabled
		if strings.TrimSpace(token) != "" {
			c.Token = token
		}
		return nil
	})
}

// DeleteCredential removes a credential unless referenced by a certificate.
func (s *Server) DeleteCredential(id string) error {
	return s.st.WithState(true, func(st *domain.State) error {
		if _, ok := st.Credentials[id]; !ok {
			return errNotFound
		}
		if n := credentialRefCount(st, id); n > 0 {
			return fmt.Errorf("credential is used by %d certificate(s); cannot delete", n)
		}
		delete(st.Credentials, id)
		return nil
	})
}

// MaskedToken returns a display-only form of the token (last 4 chars).
func MaskedToken(token string) string {
	if len(token) <= 4 {
		return "••••••"
	}
	return "••••••••••••" + token[len(token)-4:]
}

func credentialRefCount(st *domain.State, id string) int {
	n := 0
	for _, c := range st.Certificates {
		if c.CredentialID == id {
			n++
		}
	}
	return n
}
