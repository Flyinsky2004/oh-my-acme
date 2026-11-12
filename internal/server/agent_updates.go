package server

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/Flyinsky2004/oh-my-acme/internal/domain"
	"github.com/Flyinsky2004/oh-my-acme/internal/updater"
)

// AgentVersionOptions is the per-Agent result of AllAgentVersions. Versions are
// newest first; Err explains why one Agent has no usable list while the page
// still renders the rest from the store snapshot.
type AgentVersionOptions struct {
	Versions []string
	Err      error
}

// fetchAgentCatalog downloads the shared GitHub release catalog. It is a
// package variable so tests can substitute a fake transport without network.
var fetchAgentCatalog = updater.FetchCatalog

// agentHealthCheckConcurrency bounds parallel health checks so one slow Agent
// cannot serialize the whole page behind N dial timeouts.
const agentHealthCheckConcurrency = 6

// agentBatchPrecheckTimeout bounds the discovery phase of
// StartAllAgentUpdates (health checks plus the shared catalog download). It is
// deliberately separate from the per-Agent install context, which runs in the
// Server lifecycle with its own five-minute budget.
var agentBatchPrecheckTimeout = 30 * time.Second

var (
	errAgentDisabled         = errors.New("agent is disabled")
	errAgentUnregistered     = errors.New("agent is not registered")
	errAgentPlatformUnknown  = errors.New("agent must be manually upgraded once before Web updates are available")
	errAgentUpdateRunning    = errors.New("agent update is already running")
	errAgentVersionUnchanged = errors.New("agent is already at the requested version")
)

// AllAgentVersions refreshes every registered Agent's live version/platform
// and returns the stable upgrade targets for each one. The GitHub release
// listing is downloaded once and filtered in memory per Agent, so the cost does
// not grow with the number of Agents. A shared catalog error is returned as the
// second value while the map still carries per-Agent options.
func (s *Server) AllAgentVersions(ctx context.Context) (map[string]AgentVersionOptions, error) {
	initial := s.st.State()
	if len(initial.Agents) == 0 {
		return map[string]AgentVersionOptions{}, nil
	}

	ids := make([]string, 0, len(initial.Agents))
	skipped := make(map[string]error, len(initial.Agents))
	for id, agent := range initial.Agents {
		ids = append(ids, id)
		if reason := agentRefreshSkipReason(agent); reason != nil {
			skipped[id] = reason
		}
	}

	healthErrs := s.refreshAgents(ctx, ids, skipped)
	current := s.st.State()
	if err := ctx.Err(); err != nil {
		return agentVersionErrors(ids, skipped, healthErrs, err), err
	}

	options := make(map[string]AgentVersionOptions, len(ids))
	for _, id := range ids {
		agent := current.Agents[id]
		if agent == nil {
			continue
		}
		if reason, ok := skipped[id]; ok {
			options[id] = AgentVersionOptions{Err: reason}
			continue
		}
		if err := healthErrs[id]; err != nil {
			options[id] = AgentVersionOptions{Err: fmt.Errorf("agent health check failed: %w", err)}
			continue
		}
		if agent.GOOS == "" || agent.GOARCH == "" {
			options[id] = AgentVersionOptions{Err: errAgentPlatformUnknown}
			continue
		}
		options[id] = AgentVersionOptions{}
	}

	catalog, err := fetchAgentCatalog(ctx)
	if err == nil && catalog == nil {
		err = errors.New("release catalog is unavailable")
	}
	if err != nil {
		for id, option := range options {
			if option.Err == nil {
				options[id] = AgentVersionOptions{Err: err}
			}
		}
		return options, err
	}

	for id, option := range options {
		if option.Err != nil {
			continue
		}
		agent := current.Agents[id]
		if agent == nil {
			delete(options, id)
			continue
		}
		versions, err := catalog.AvailableFor(updater.ComponentAgent, agent.Version, agent.GOOS, agent.GOARCH)
		if err != nil {
			options[id] = AgentVersionOptions{Err: err}
			continue
		}
		options[id] = AgentVersionOptions{Versions: versions}
	}
	return options, nil
}

// agentVersionErrors builds the map returned when the caller's context ends
// before the catalog can be consulted. Every initial Agent gets an explicit
// entry so a missing key is never mistaken for "already up to date".
func agentVersionErrors(ids []string, skipped map[string]error, healthErrs map[string]error, ctxErr error) map[string]AgentVersionOptions {
	options := make(map[string]AgentVersionOptions, len(ids))
	for _, id := range ids {
		if reason, ok := skipped[id]; ok {
			options[id] = AgentVersionOptions{Err: reason}
			continue
		}
		if err := healthErrs[id]; err != nil {
			options[id] = AgentVersionOptions{Err: fmt.Errorf("agent health check failed: %w", err)}
			continue
		}
		options[id] = AgentVersionOptions{Err: ctxErr}
	}
	return options
}

// agentRefreshSkipReason reports Agents that must not be health-checked:
// refreshing a disabled or unregistered node would activate it.
func agentRefreshSkipReason(agent *domain.Agent) error {
	if agent == nil {
		return errNotFound
	}
	switch agent.Status {
	case domain.AgentDisabled:
		return errAgentDisabled
	case domain.AgentUnregistered:
		return errAgentUnregistered
	}
	return nil
}

// refreshAgents health-checks the eligible Agents with bounded concurrency. It
// respects the caller's deadline and returns one result per checked Agent.
func (s *Server) refreshAgents(ctx context.Context, ids []string, skipped map[string]error) map[string]error {
	results := make(map[string]error, len(ids))
	pending := make([]string, 0, len(ids))
	for _, id := range ids {
		if _, ok := skipped[id]; !ok {
			pending = append(pending, id)
		}
	}
	if len(pending) == 0 {
		return results
	}

	timeout := s.agentDialTimeout()
	var mu sync.Mutex
	sem := make(chan struct{}, agentHealthCheckConcurrency)
	var wg sync.WaitGroup
	for _, id := range pending {
		id := id
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				mu.Lock()
				results[id] = ctx.Err()
				mu.Unlock()
				return
			}
			agentCtx, cancel := context.WithTimeout(ctx, timeout)
			err := s.RefreshAgent(agentCtx, id)
			cancel()
			mu.Lock()
			results[id] = err
			mu.Unlock()
		}()
	}
	wg.Wait()
	return results
}

// StartAllAgentUpdates starts one update per eligible Agent in the Server
// lifecycle, choosing each Agent's newest compatible stable release. Agents
// that are already running an update, already current, disabled, unregistered,
// unreachable or missing platform information are skipped; one failure never
// stops the others. The shared catalog is downloaded once.
func (s *Server) StartAllAgentUpdates() (started int, skipped int, err error) {
	// Discovery is bounded so a large set of slow Agents cannot hold the
	// request for N/concurrency health-check waves. Only the pre-check ends on
	// timeout; each accepted install below runs in the Server lifecycle.
	ctx, cancel := context.WithTimeout(s.ctx, agentBatchPrecheckTimeout)
	options, err := s.AllAgentVersions(ctx)
	precheckErr := ctx.Err()
	cancel()
	if err != nil {
		return 0, 0, err
	}
	if precheckErr != nil {
		return 0, 0, precheckErr
	}

	current := s.st.State()
	var errs []error
	for id, option := range options {
		agent := current.Agents[id]
		if agent == nil {
			skipped++
			continue
		}
		if agent.UpdateStatus == domain.StatusRunning || option.Err != nil || len(option.Versions) == 0 {
			skipped++
			continue
		}
		target := option.Versions[0]
		if claimErr := s.claimAgentUpdate(id, target); claimErr != nil {
			skipped++
			if !errors.Is(claimErr, errAgentUpdateRunning) && !errors.Is(claimErr, errAgentVersionUnchanged) {
				errs = append(errs, fmt.Errorf("agent %s: %w", id, claimErr))
			}
			continue
		}
		started++
		s.Go(func(parent context.Context) {
			ctx, cancel := context.WithTimeout(parent, 5*time.Minute)
			defer cancel()
			if err := s.updateAgent(ctx, id, target); err != nil {
				_ = s.setAgentUpdateState(id, domain.StatusFailed, target, err.Error())
				s.log.Error("agent update failed", "agent_id", id, "target", target, "err", err)
			}
		})
	}
	return started, skipped, errors.Join(errs...)
}

// claimAgentUpdate atomically reserves an Agent for one update. Both the single
// and batch entry points use it, so concurrent requests cannot start two
// updates for the same Agent.
func (s *Server) claimAgentUpdate(agentID, targetVersion string) error {
	return s.st.WithState(true, func(st *domain.State) error {
		agent := st.Agents[agentID]
		if agent == nil {
			return errNotFound
		}
		if agent.UpdateStatus == domain.StatusRunning {
			return errAgentUpdateRunning
		}
		if agent.Version == targetVersion {
			return errAgentVersionUnchanged
		}
		agent.UpdateStatus = domain.StatusRunning
		agent.UpdateTargetVersion = targetVersion
		agent.UpdateError = ""
		return nil
	})
}
