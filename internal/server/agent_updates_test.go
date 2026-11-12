package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Flyinsky2004/oh-my-acme/internal/domain"
	"github.com/Flyinsky2004/oh-my-acme/internal/protocol"
	"github.com/Flyinsky2004/oh-my-acme/internal/store"
	"github.com/Flyinsky2004/oh-my-acme/internal/updater"
)

const (
	agentUpdatesAMD64Asset = "oh-my-acme-agent_linux_amd64.tar.gz"
	agentUpdatesARM64Asset = "oh-my-acme-agent_linux_arm64.tar.gz"
	agentUpdatesChecksums  = "checksums.txt"
)

type agentUpdatesRoundTrip func(*http.Request) (*http.Response, error)

func (f agentUpdatesRoundTrip) Do(req *http.Request) (*http.Response, error) { return f(req) }

// agentUpdatesInstallCatalog replaces the shared catalog fetch with an
// in-memory release listing and returns a counter of fetch calls.
func agentUpdatesInstallCatalog(t *testing.T, releases []map[string]any) *int32 {
	t.Helper()
	body, err := json.Marshal(releases)
	if err != nil {
		t.Fatal(err)
	}
	var fetches int32
	previous := fetchAgentCatalog
	fetchAgentCatalog = func(ctx context.Context) (*updater.Catalog, error) {
		atomic.AddInt32(&fetches, 1)
		client := agentUpdatesRoundTrip(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader(body)),
				Header:     make(http.Header),
			}, nil
		})
		return updater.FetchCatalogWithClient(ctx, client)
	}
	t.Cleanup(func() { fetchAgentCatalog = previous })
	return &fetches
}

func agentUpdatesRelease(id int64, tag string, names ...string) map[string]any {
	assets := make([]map[string]any, 0, len(names))
	for i, name := range names {
		assets = append(assets, map[string]any{"id": id + int64(i), "name": name})
	}
	return map[string]any{"tag_name": tag, "assets": assets}
}

// agentUpdatesFake is a minimal mTLS Agent endpoint for health and update.
type agentUpdatesFake struct {
	server *httptest.Server
	id     string

	mu           sync.Mutex
	version      string
	goos         string
	goarch       string
	healthStatus int
	healthBlock  <-chan struct{}
	rejectUpdate bool
	blockUpdate  <-chan struct{}
	updates      []string
	healthCalls  int
}

func newAgentUpdatesFake(t *testing.T, pool *x509.CertPool, id, version, goos, goarch string) *agentUpdatesFake {
	t.Helper()
	f := &agentUpdatesFake{id: id, version: version, goos: goos, goarch: goarch}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.healthCalls++
		status := f.healthStatus
		block := f.healthBlock
		version, gos, arch := f.version, f.goos, f.goarch
		f.mu.Unlock()
		if block != nil {
			select {
			case <-block:
			case <-r.Context().Done():
				return
			}
		}
		if status != 0 {
			w.WriteHeader(status)
			return
		}
		writeJSON(w, protocol.HealthResponse{AgentID: f.id, Version: version, GOOS: gos, GOARCH: arch})
	})
	mux.HandleFunc("POST /v1/update", func(w http.ResponseWriter, r *http.Request) {
		var req protocol.UpdateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		f.updates = append(f.updates, req.Version)
		block := f.blockUpdate
		reject := f.rejectUpdate
		f.mu.Unlock()
		if block != nil {
			select {
			case <-block:
			case <-r.Context().Done():
				return
			}
		}
		if reject {
			writeJSON(w, protocol.UpdateResponse{Success: false, Error: "update rejected"})
			return
		}
		f.mu.Lock()
		f.version = req.Version
		f.mu.Unlock()
		writeJSON(w, protocol.UpdateResponse{Success: true, AgentID: f.id, TargetVersion: req.Version})
	})
	f.server = httptest.NewTLSServer(mux)
	t.Cleanup(f.server.Close)
	pool.AddCert(f.server.Certificate())
	return f
}

func (f *agentUpdatesFake) address(t *testing.T) (string, int) {
	t.Helper()
	return agentUpdatesServerAddress(t, f.server)
}

func agentUpdatesServerAddress(t *testing.T, server *httptest.Server) (string, int) {
	t.Helper()
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	host, portText, err := net.SplitHostPort(parsed.Host)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	return host, port
}

func (f *agentUpdatesFake) updateVersions() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.updates...)
}

func (f *agentUpdatesFake) healthCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.healthCalls
}

func (f *agentUpdatesFake) setHealthStatus(status int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.healthStatus = status
}

func newAgentUpdatesStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func newAgentUpdatesTestServer(t *testing.T, st *store.Store, pool *x509.CertPool) *Server {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	srv := &Server{
		st:        st,
		log:       slog.Default(),
		ctx:       ctx,
		cancel:    cancel,
		cliTLSCfg: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
	}
	t.Cleanup(func() {
		cancel()
		srv.wg.Wait()
	})
	return srv
}

func addAgentUpdatesAgent(t *testing.T, st *store.Store, agent *domain.Agent) {
	t.Helper()
	if err := st.WithState(true, func(state *domain.State) error {
		state.Agents[agent.ID] = agent
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func agentUpdatesRegisteredAgent(t *testing.T, fake *agentUpdatesFake, version string) *domain.Agent {
	t.Helper()
	address, port := fake.address(t)
	return &domain.Agent{
		ID: fake.id, Name: fake.id, Address: address, Port: port,
		Status: domain.AgentRegistered, Version: version, GOOS: fake.goos, GOARCH: fake.goarch,
	}
}

func waitForAgentUpdate(t *testing.T, fake *agentUpdatesFake, version string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		for _, got := range fake.updateVersions() {
			if got == version {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%s did not receive update %s; got %v", fake.id, version, fake.updateVersions())
}

func waitForAgentUpdateStatus(t *testing.T, st *store.Store, agentID string, want domain.OperationStatus) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		agent := st.State().Agents[agentID]
		if agent != nil && agent.UpdateStatus == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%s update status = %+v, want %s", agentID, st.State().Agents[agentID], want)
}

func TestAllAgentVersionsUsesOneCatalogForEveryAgent(t *testing.T) {
	st := newAgentUpdatesStore(t)
	pool := x509.NewCertPool()
	amd64 := newAgentUpdatesFake(t, pool, "agent-amd64", "1.0.0", "linux", "amd64")
	arm64 := newAgentUpdatesFake(t, pool, "agent-arm64", "1.0.0", "linux", "arm64")
	addAgentUpdatesAgent(t, st, agentUpdatesRegisteredAgent(t, amd64, "1.0.0"))
	addAgentUpdatesAgent(t, st, agentUpdatesRegisteredAgent(t, arm64, "1.0.0"))
	fetches := agentUpdatesInstallCatalog(t, []map[string]any{
		agentUpdatesRelease(1, "v1.5.0", agentUpdatesAMD64Asset, agentUpdatesARM64Asset, agentUpdatesChecksums),
		agentUpdatesRelease(10, "v2.0.0", agentUpdatesAMD64Asset, agentUpdatesChecksums),
	})
	srv := newAgentUpdatesTestServer(t, st, pool)

	options, err := srv.AllAgentVersions(context.Background())
	if err != nil {
		t.Fatalf("AllAgentVersions() error = %v", err)
	}
	if got := atomic.LoadInt32(fetches); got != 1 {
		t.Fatalf("catalog fetches = %d, want 1", got)
	}
	if got := fmt.Sprint(options["agent-amd64"].Versions); got != "[v2.0.0 v1.5.0]" {
		t.Fatalf("amd64 versions = %s", got)
	}
	if got := fmt.Sprint(options["agent-arm64"].Versions); got != "[v1.5.0]" {
		t.Fatalf("arm64 versions = %s", got)
	}
	current := st.State()
	if current.Agents["agent-amd64"].Version != "1.0.0" || current.Agents["agent-amd64"].GOOS != "linux" {
		t.Fatalf("refresh was not persisted: %+v", current.Agents["agent-amd64"])
	}
}

func TestAllAgentVersionsExplainsNonUpdatableAgents(t *testing.T) {
	st := newAgentUpdatesStore(t)
	pool := x509.NewCertPool()
	healthy := newAgentUpdatesFake(t, pool, "healthy", "1.0.0", "linux", "amd64")
	latest := newAgentUpdatesFake(t, pool, "latest", "2.0.0", "linux", "amd64")
	noPlatform := newAgentUpdatesFake(t, pool, "no-platform", "1.0.0", "", "")
	dev := newAgentUpdatesFake(t, pool, "dev", "dev", "linux", "amd64")
	unsupported := newAgentUpdatesFake(t, pool, "unsupported", "1.0.0", "darwin", "amd64")
	unreachable := newAgentUpdatesFake(t, pool, "unreachable", "1.0.0", "linux", "amd64")
	unreachable.setHealthStatus(http.StatusInternalServerError)
	disabled := newAgentUpdatesFake(t, pool, "disabled", "1.0.0", "linux", "amd64")
	unregistered := newAgentUpdatesFake(t, pool, "unregistered", "1.0.0", "linux", "amd64")

	addAgentUpdatesAgent(t, st, agentUpdatesRegisteredAgent(t, healthy, "1.0.0"))
	addAgentUpdatesAgent(t, st, agentUpdatesRegisteredAgent(t, latest, "2.0.0"))
	addAgentUpdatesAgent(t, st, agentUpdatesRegisteredAgent(t, noPlatform, "1.0.0"))
	addAgentUpdatesAgent(t, st, agentUpdatesRegisteredAgent(t, dev, "dev"))
	addAgentUpdatesAgent(t, st, agentUpdatesRegisteredAgent(t, unsupported, "1.0.0"))
	addAgentUpdatesAgent(t, st, agentUpdatesRegisteredAgent(t, unreachable, "1.0.0"))
	disabledAgent := agentUpdatesRegisteredAgent(t, disabled, "1.0.0")
	disabledAgent.Status = domain.AgentDisabled
	addAgentUpdatesAgent(t, st, disabledAgent)
	unregisteredAgent := agentUpdatesRegisteredAgent(t, unregistered, "1.0.0")
	unregisteredAgent.Status = domain.AgentUnregistered
	addAgentUpdatesAgent(t, st, unregisteredAgent)

	fetches := agentUpdatesInstallCatalog(t, []map[string]any{
		agentUpdatesRelease(1, "v2.0.0", agentUpdatesAMD64Asset, agentUpdatesChecksums),
	})
	srv := newAgentUpdatesTestServer(t, st, pool)

	options, err := srv.AllAgentVersions(context.Background())
	if err != nil {
		t.Fatalf("AllAgentVersions() error = %v", err)
	}
	if got := atomic.LoadInt32(fetches); got != 1 {
		t.Fatalf("catalog fetches = %d, want 1", got)
	}
	if got := fmt.Sprint(options["healthy"].Versions); got != "[v2.0.0]" || options["healthy"].Err != nil {
		t.Fatalf("healthy = %+v", options["healthy"])
	}
	if len(options["latest"].Versions) != 0 || options["latest"].Err != nil {
		t.Fatalf("latest = %+v, want empty versions and no error", options["latest"])
	}
	if !errors.Is(options["no-platform"].Err, errAgentPlatformUnknown) {
		t.Fatalf("no-platform error = %v", options["no-platform"].Err)
	}
	if options["dev"].Err == nil {
		t.Fatal("dev version was accepted")
	}
	if options["unsupported"].Err == nil || !strings.Contains(options["unsupported"].Err.Error(), "unsupported platform") {
		t.Fatalf("unsupported platform error = %v", options["unsupported"].Err)
	}
	if options["unreachable"].Err == nil || !strings.Contains(options["unreachable"].Err.Error(), "health check failed") {
		t.Fatalf("unreachable error = %v", options["unreachable"].Err)
	}
	if !errors.Is(options["disabled"].Err, errAgentDisabled) {
		t.Fatalf("disabled error = %v", options["disabled"].Err)
	}
	if !errors.Is(options["unregistered"].Err, errAgentUnregistered) {
		t.Fatalf("unregistered error = %v", options["unregistered"].Err)
	}
	if disabled.healthCount() != 0 || unregistered.healthCount() != 0 {
		t.Fatal("disabled/unregistered agents were health-checked")
	}
	current := st.State()
	if current.Agents["disabled"].Status != domain.AgentDisabled {
		t.Fatalf("disabled agent was activated: %s", current.Agents["disabled"].Status)
	}
	if current.Agents["unregistered"].Status != domain.AgentUnregistered {
		t.Fatalf("unregistered agent was activated: %s", current.Agents["unregistered"].Status)
	}
}

func TestAllAgentVersionsEmptyStoreDoesNotFetch(t *testing.T) {
	st := newAgentUpdatesStore(t)
	fetches := agentUpdatesInstallCatalog(t, nil)
	srv := newAgentUpdatesTestServer(t, st, x509.NewCertPool())

	options, err := srv.AllAgentVersions(context.Background())
	if err != nil {
		t.Fatalf("AllAgentVersions() error = %v", err)
	}
	if len(options) != 0 {
		t.Fatalf("options = %v, want empty", options)
	}
	if got := atomic.LoadInt32(fetches); got != 0 {
		t.Fatalf("catalog fetches = %d, want 0", got)
	}
}

func TestAllAgentVersionsCatalogFailureKeepsPerAgentEntries(t *testing.T) {
	st := newAgentUpdatesStore(t)
	pool := x509.NewCertPool()
	fake := newAgentUpdatesFake(t, pool, "agent", "1.0.0", "linux", "amd64")
	addAgentUpdatesAgent(t, st, agentUpdatesRegisteredAgent(t, fake, "1.0.0"))

	previous := fetchAgentCatalog
	fetchAgentCatalog = func(context.Context) (*updater.Catalog, error) {
		return nil, errors.New("github unavailable")
	}
	t.Cleanup(func() { fetchAgentCatalog = previous })
	srv := newAgentUpdatesTestServer(t, st, pool)

	options, err := srv.AllAgentVersions(context.Background())
	if err == nil || !strings.Contains(err.Error(), "github unavailable") {
		t.Fatalf("AllAgentVersions() error = %v, want catalog failure", err)
	}
	if options["agent"].Err == nil {
		t.Fatal("per-agent options lost the catalog error")
	}
}

func TestStartAllAgentUpdatesSelectsNewestAndSkips(t *testing.T) {
	st := newAgentUpdatesStore(t)
	pool := x509.NewCertPool()
	amd64 := newAgentUpdatesFake(t, pool, "amd64", "1.0.0", "linux", "amd64")
	arm64 := newAgentUpdatesFake(t, pool, "arm64", "1.0.0", "linux", "arm64")
	failing := newAgentUpdatesFake(t, pool, "failing", "1.0.0", "linux", "amd64")
	failing.mu.Lock()
	failing.rejectUpdate = true
	failing.mu.Unlock()
	latest := newAgentUpdatesFake(t, pool, "latest", "2.0.0", "linux", "amd64")
	noPlatform := newAgentUpdatesFake(t, pool, "no-platform", "1.0.0", "", "")
	unreachable := newAgentUpdatesFake(t, pool, "unreachable", "1.0.0", "linux", "amd64")
	unreachable.setHealthStatus(http.StatusInternalServerError)
	disabled := newAgentUpdatesFake(t, pool, "disabled", "1.0.0", "linux", "amd64")
	unregistered := newAgentUpdatesFake(t, pool, "unregistered", "1.0.0", "linux", "amd64")
	running := newAgentUpdatesFake(t, pool, "running", "1.0.0", "linux", "amd64")

	addAgentUpdatesAgent(t, st, agentUpdatesRegisteredAgent(t, amd64, "1.0.0"))
	addAgentUpdatesAgent(t, st, agentUpdatesRegisteredAgent(t, arm64, "1.0.0"))
	addAgentUpdatesAgent(t, st, agentUpdatesRegisteredAgent(t, failing, "1.0.0"))
	addAgentUpdatesAgent(t, st, agentUpdatesRegisteredAgent(t, latest, "2.0.0"))
	addAgentUpdatesAgent(t, st, agentUpdatesRegisteredAgent(t, noPlatform, "1.0.0"))
	addAgentUpdatesAgent(t, st, agentUpdatesRegisteredAgent(t, unreachable, "1.0.0"))
	disabledAgent := agentUpdatesRegisteredAgent(t, disabled, "1.0.0")
	disabledAgent.Status = domain.AgentDisabled
	addAgentUpdatesAgent(t, st, disabledAgent)
	unregisteredAgent := agentUpdatesRegisteredAgent(t, unregistered, "1.0.0")
	unregisteredAgent.Status = domain.AgentUnregistered
	addAgentUpdatesAgent(t, st, unregisteredAgent)
	runningAgent := agentUpdatesRegisteredAgent(t, running, "1.0.0")
	runningAgent.UpdateStatus = domain.StatusRunning
	runningAgent.UpdateTargetVersion = "v1.5.0"
	addAgentUpdatesAgent(t, st, runningAgent)

	fetches := agentUpdatesInstallCatalog(t, []map[string]any{
		agentUpdatesRelease(1, "v1.5.0", agentUpdatesAMD64Asset, agentUpdatesARM64Asset, agentUpdatesChecksums),
		agentUpdatesRelease(10, "v2.0.0", agentUpdatesAMD64Asset, agentUpdatesARM64Asset, agentUpdatesChecksums),
	})
	srv := newAgentUpdatesTestServer(t, st, pool)

	started, skipped, err := srv.StartAllAgentUpdates()
	if err != nil {
		t.Fatalf("StartAllAgentUpdates() error = %v", err)
	}
	if started != 3 || skipped != 6 {
		t.Fatalf("started=%d skipped=%d, want 3/6", started, skipped)
	}
	if got := atomic.LoadInt32(fetches); got != 1 {
		t.Fatalf("catalog fetches = %d, want 1", got)
	}

	waitForAgentUpdate(t, amd64, "v2.0.0")
	waitForAgentUpdate(t, arm64, "v2.0.0")
	waitForAgentUpdate(t, failing, "v2.0.0")
	waitForAgentUpdateStatus(t, st, "failing", domain.StatusFailed)
	if updates := amd64.updateVersions(); len(updates) != 1 {
		t.Fatalf("amd64 updates = %v, want one after another Agent failed", updates)
	}
	for _, fake := range []*agentUpdatesFake{latest, noPlatform, unreachable, disabled, unregistered, running} {
		if updates := fake.updateVersions(); len(updates) != 0 {
			t.Fatalf("%s received updates %v, want none", fake.id, updates)
		}
	}
	current := st.State()
	if current.Agents["disabled"].Status != domain.AgentDisabled {
		t.Fatalf("disabled agent was activated: %s", current.Agents["disabled"].Status)
	}
	if current.Agents["unregistered"].Status != domain.AgentUnregistered {
		t.Fatalf("unregistered agent was activated: %s", current.Agents["unregistered"].Status)
	}
	if current.Agents["running"].UpdateStatus != domain.StatusRunning {
		t.Fatalf("running agent state = %s", current.Agents["running"].UpdateStatus)
	}
}

func TestStartAllAgentUpdatesCatalogFailureStartsNothing(t *testing.T) {
	st := newAgentUpdatesStore(t)
	pool := x509.NewCertPool()
	fake := newAgentUpdatesFake(t, pool, "agent", "1.0.0", "linux", "amd64")
	addAgentUpdatesAgent(t, st, agentUpdatesRegisteredAgent(t, fake, "1.0.0"))

	previous := fetchAgentCatalog
	fetchAgentCatalog = func(context.Context) (*updater.Catalog, error) {
		return nil, errors.New("offline")
	}
	t.Cleanup(func() { fetchAgentCatalog = previous })
	srv := newAgentUpdatesTestServer(t, st, pool)

	started, skipped, err := srv.StartAllAgentUpdates()
	if err == nil {
		t.Fatal("StartAllAgentUpdates() succeeded without a catalog")
	}
	if started != 0 || skipped != 0 {
		t.Fatalf("started=%d skipped=%d, want 0/0", started, skipped)
	}
	if got := st.State().Agents["agent"].UpdateStatus; got == domain.StatusRunning {
		t.Fatal("agent was claimed despite catalog failure")
	}
}

func TestClaimAgentUpdateAllowsOneConcurrentWinner(t *testing.T) {
	st := newAgentUpdatesStore(t)
	srv := newAgentUpdatesTestServer(t, st, x509.NewCertPool())
	addAgentUpdatesAgent(t, st, &domain.Agent{ID: "agent", Status: domain.AgentRegistered, Version: "v1.0.0"})

	const workers = 12
	var wg sync.WaitGroup
	var winners, busy int32
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			switch err := srv.claimAgentUpdate("agent", "v2.0.0"); {
			case err == nil:
				atomic.AddInt32(&winners, 1)
			case errors.Is(err, errAgentUpdateRunning):
				atomic.AddInt32(&busy, 1)
			default:
				t.Errorf("claimAgentUpdate() error = %v", err)
			}
		}()
	}
	wg.Wait()
	if winners != 1 || busy != workers-1 {
		t.Fatalf("winners=%d busy=%d, want 1/%d", winners, busy, workers-1)
	}
	agent := st.State().Agents["agent"]
	if agent.UpdateStatus != domain.StatusRunning || agent.UpdateTargetVersion != "v2.0.0" {
		t.Fatalf("agent = %+v", agent)
	}
}

func TestStartAgentUpdateRejectsAlreadyRunning(t *testing.T) {
	st := newAgentUpdatesStore(t)
	pool := x509.NewCertPool()
	fake := newAgentUpdatesFake(t, pool, "agent", "1.0.0", "linux", "amd64")
	agent := agentUpdatesRegisteredAgent(t, fake, "1.0.0")
	agent.UpdateStatus = domain.StatusRunning
	agent.UpdateTargetVersion = "v1.5.0"
	addAgentUpdatesAgent(t, st, agent)
	agentUpdatesInstallCatalog(t, []map[string]any{
		agentUpdatesRelease(1, "v2.0.0", agentUpdatesAMD64Asset, agentUpdatesChecksums),
	})
	srv := newAgentUpdatesTestServer(t, st, pool)

	err := srv.StartAgentUpdate("agent", "v2.0.0")
	if !errors.Is(err, errAgentUpdateRunning) {
		t.Fatalf("StartAgentUpdate() error = %v, want already running", err)
	}
	if updates := fake.updateVersions(); len(updates) != 0 {
		t.Fatalf("updates = %v, want none", updates)
	}
	if got := st.State().Agents["agent"].UpdateTargetVersion; got != "v1.5.0" {
		t.Fatalf("target = %q, want the original v1.5.0", got)
	}
}

func TestAllAgentVersionsContextEndIncludesSuccessfulHealthChecks(t *testing.T) {
	st := newAgentUpdatesStore(t)
	pool := x509.NewCertPool()
	fast := newAgentUpdatesFake(t, pool, "fast", "1.0.0", "linux", "amd64")
	slow := newAgentUpdatesFake(t, pool, "slow", "1.0.0", "linux", "amd64")
	block := make(chan struct{})
	slow.mu.Lock()
	slow.healthBlock = block
	slow.mu.Unlock()
	addAgentUpdatesAgent(t, st, agentUpdatesRegisteredAgent(t, fast, "1.0.0"))
	addAgentUpdatesAgent(t, st, agentUpdatesRegisteredAgent(t, slow, "1.0.0"))
	agentUpdatesInstallCatalog(t, []map[string]any{
		agentUpdatesRelease(1, "v2.0.0", agentUpdatesAMD64Asset, agentUpdatesChecksums),
	})
	srv := newAgentUpdatesTestServer(t, st, pool)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	options, err := srv.AllAgentVersions(ctx)
	if err == nil {
		t.Fatal("AllAgentVersions() ignored the context deadline")
	}
	if len(options) != 2 {
		t.Fatalf("options = %d entries, want every initial Agent", len(options))
	}
	for _, id := range []string{"fast", "slow"} {
		option, ok := options[id]
		if !ok {
			t.Fatalf("%s missing from options", id)
		}
		if option.Err == nil {
			t.Fatalf("%s has no error after the context ended: %+v", id, option)
		}
		if len(option.Versions) != 0 {
			t.Fatalf("%s reported versions %v without a completed pre-check", id, option.Versions)
		}
	}
}

func TestStartAllAgentUpdatesPrecheckTimeoutStartsNothing(t *testing.T) {
	st := newAgentUpdatesStore(t)
	pool := x509.NewCertPool()
	block := make(chan struct{})
	first := newAgentUpdatesFake(t, pool, "first", "1.0.0", "linux", "amd64")
	second := newAgentUpdatesFake(t, pool, "second", "1.0.0", "linux", "amd64")
	for _, fake := range []*agentUpdatesFake{first, second} {
		fake.mu.Lock()
		fake.healthBlock = block
		fake.mu.Unlock()
		addAgentUpdatesAgent(t, st, agentUpdatesRegisteredAgent(t, fake, "1.0.0"))
	}
	agentUpdatesInstallCatalog(t, []map[string]any{
		agentUpdatesRelease(1, "v2.0.0", agentUpdatesAMD64Asset, agentUpdatesChecksums),
	})
	srv := newAgentUpdatesTestServer(t, st, pool)

	previous := agentBatchPrecheckTimeout
	agentBatchPrecheckTimeout = 100 * time.Millisecond
	t.Cleanup(func() { agentBatchPrecheckTimeout = previous })

	start := time.Now()
	started, skipped, err := srv.StartAllAgentUpdates()
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("StartAllAgentUpdates() succeeded after the pre-check timed out")
	}
	if started != 0 || skipped != 0 {
		t.Fatalf("started=%d skipped=%d, want 0/0", started, skipped)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("pre-check took %s, want a bounded wait", elapsed)
	}
	for _, fake := range []*agentUpdatesFake{first, second} {
		if updates := fake.updateVersions(); len(updates) != 0 {
			t.Fatalf("%s received updates %v after a timed-out pre-check", fake.id, updates)
		}
	}
	current := st.State()
	for _, id := range []string{"first", "second"} {
		if current.Agents[id].UpdateStatus == domain.StatusRunning {
			t.Fatalf("%s was claimed after a timed-out pre-check", id)
		}
	}
}

func TestStartAllAgentUpdatesDoesNotStartDuplicate(t *testing.T) {
	st := newAgentUpdatesStore(t)
	pool := x509.NewCertPool()
	block := make(chan struct{})
	fake := newAgentUpdatesFake(t, pool, "agent", "1.0.0", "linux", "amd64")
	fake.mu.Lock()
	fake.blockUpdate = block
	fake.mu.Unlock()
	addAgentUpdatesAgent(t, st, agentUpdatesRegisteredAgent(t, fake, "1.0.0"))
	agentUpdatesInstallCatalog(t, []map[string]any{
		agentUpdatesRelease(1, "v2.0.0", agentUpdatesAMD64Asset, agentUpdatesChecksums),
	})
	srv := newAgentUpdatesTestServer(t, st, pool)

	started, skipped, err := srv.StartAllAgentUpdates()
	if err != nil || started != 1 || skipped != 0 {
		t.Fatalf("first start = %d/%d/%v, want 1/0/nil", started, skipped, err)
	}
	started, skipped, err = srv.StartAllAgentUpdates()
	if err != nil || started != 0 || skipped != 1 {
		t.Fatalf("second start = %d/%d/%v, want 0/1/nil", started, skipped, err)
	}
	waitForAgentUpdate(t, fake, "v2.0.0")
	time.Sleep(50 * time.Millisecond)
	if updates := fake.updateVersions(); len(updates) != 1 {
		t.Fatalf("updates = %v, want exactly one", updates)
	}
	close(block)
}

type agentUpdatesConcurrency struct {
	current int32
	max     int32
}

func (c *agentUpdatesConcurrency) enter() {
	n := atomic.AddInt32(&c.current, 1)
	for {
		m := atomic.LoadInt32(&c.max)
		if n <= m || atomic.CompareAndSwapInt32(&c.max, m, n) {
			return
		}
	}
}

func (c *agentUpdatesConcurrency) leave() { atomic.AddInt32(&c.current, -1) }

func (c *agentUpdatesConcurrency) maximum() int32 { return atomic.LoadInt32(&c.max) }

func TestAllAgentVersionsRespectsContextDeadlineAndBoundsConcurrency(t *testing.T) {
	st := newAgentUpdatesStore(t)
	pool := x509.NewCertPool()
	tracker := &agentUpdatesConcurrency{}
	const agents = 12
	for i := 0; i < agents; i++ {
		id := fmt.Sprintf("agent-%02d", i)
		mux := http.NewServeMux()
		mux.HandleFunc("GET /v1/health", func(w http.ResponseWriter, r *http.Request) {
			tracker.enter()
			defer tracker.leave()
			<-r.Context().Done()
		})
		server := httptest.NewTLSServer(mux)
		t.Cleanup(server.Close)
		pool.AddCert(server.Certificate())
		address, port := agentUpdatesServerAddress(t, server)
		addAgentUpdatesAgent(t, st, &domain.Agent{
			ID: id, Address: address, Port: port, Status: domain.AgentRegistered,
			Version: "1.0.0", GOOS: "linux", GOARCH: "amd64",
		})
	}
	agentUpdatesInstallCatalog(t, nil)
	srv := newAgentUpdatesTestServer(t, st, pool)

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	options, err := srv.AllAgentVersions(ctx)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("AllAgentVersions() ignored the context deadline")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("AllAgentVersions() took %s, want a bounded wait", elapsed)
	}
	if len(options) != agents {
		t.Fatalf("options = %d entries, want %d", len(options), agents)
	}
	for id, option := range options {
		if option.Err == nil {
			t.Fatalf("%s has no error after a canceled refresh", id)
		}
	}
	if max := tracker.maximum(); max < 2 || max > agentHealthCheckConcurrency {
		t.Fatalf("max concurrent health checks = %d, want 2..%d", max, agentHealthCheckConcurrency)
	}
}
