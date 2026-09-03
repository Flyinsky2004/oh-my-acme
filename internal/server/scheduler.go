package server

import (
	"context"
	"hash/fnv"
	"log/slog"
	"time"

	"github.com/Flyinsky2004/oh-my-acme/internal/domain"
)

// Scheduler runs a background loop that periodically scans enabled certificates
// and auto-renews any that have entered the renewal window. Renewal is a fresh
// issuance with a new private key; on success the new version is auto-deployed
// to the certificate's target agents. Jitter is spread per certificate to
// avoid hammering the CA at once. Failures are recorded in state and surfaced
// in the Web UI for manual retry.
func (s *Server) Scheduler(ctx context.Context, checkInterval time.Duration, log *slog.Logger) {
	s.checkRenewals(ctx) // run once immediately
	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.checkRenewals(ctx)
		}
	}
}

// checkRenewals scans all certificates and renews those within window.
func (s *Server) checkRenewals(ctx context.Context) {
	st := s.st.State()
	for id, cert := range st.Certificates {
		if cert == nil || !cert.Enabled || cert.Current == nil {
			continue
		}
		if !inRenewWindow(cert, st.Config.RenewPreferenceDays) {
			continue
		}
		s.log.Info("auto-renewing certificate", "cert_id", id, "domain", cert.RootDomain)
		if err := s.Issue(ctx, id); err != nil {
			s.log.Error("auto-renew failed", "cert_id", id, "err", err)
			continue
		}
		if err := s.DeployAll(ctx, id); err != nil {
			s.log.Error("auto-deploy after renew failed", "cert_id", id, "err", err)
		}
	}
}

// inRenewWindow reports whether a certificate should be renewed now. Renewal
// is triggered at min(renewPreferenceDays, lifetime/3) before expiry, plus a
// per-certificate jitter of up to 2 hours to spread CA load.
func inRenewWindow(cert *domain.Certificate, prefDays int) bool {
	if cert.Current == nil {
		return false
	}
	if prefDays <= 0 {
		prefDays = 30
	}
	lifetime := cert.Current.ExpiresAt.Sub(cert.Current.IssuedAt)
	renewPre := time.Duration(prefDays) * 24 * time.Hour
	third := lifetime / 3
	if third < renewPre {
		renewPre = third
	}
	renewAt := cert.Current.ExpiresAt.Add(-renewPre).Add(jitter(cert.ID))
	return time.Now().After(renewAt)
}

// jitter returns a deterministic 0..2h offset derived from the cert ID so the
// same certificate renews at the same offset each cycle without clustering.
func jitter(seed string) time.Duration {
	h := fnv.New32a()
	_, _ = h.Write([]byte(seed))
	return time.Duration(h.Sum32()%7200) * time.Second
}
