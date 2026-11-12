package updater

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
)

const (
	catalogAgentAMD64  = "oh-my-acme-agent_linux_amd64.tar.gz"
	catalogAgentARM64  = "oh-my-acme-agent_linux_arm64.tar.gz"
	catalogServerAMD64 = "oh-my-acme-server_linux_amd64.tar.gz"
	catalogChecksums   = "checksums.txt"
)

// catalogFixture builds release JSON with unique asset IDs.
type catalogFixture struct {
	nextID int64
}

func (f *catalogFixture) release(tag string, draft, prerelease bool, names ...string) map[string]any {
	assets := make([]map[string]any, 0, len(names))
	for _, name := range names {
		f.nextID++
		assets = append(assets, map[string]any{"id": f.nextID, "name": name})
	}
	return map[string]any{"tag_name": tag, "draft": draft, "prerelease": prerelease, "assets": assets}
}

func TestCatalogSharesOneDownloadAcrossAgentsAndPlatforms(t *testing.T) {
	fixture := &catalogFixture{}
	page1 := []map[string]any{
		fixture.release("v1.0.0", false, false, catalogAgentAMD64, catalogAgentARM64, catalogChecksums),
		fixture.release("v1.5.0", false, false, catalogAgentAMD64, catalogAgentARM64, catalogChecksums),
		fixture.release("v2.0.0", false, false, catalogAgentAMD64, catalogChecksums),
		fixture.release("v2.1.0-rc.1", false, false, catalogAgentAMD64, catalogAgentARM64, catalogChecksums),
		fixture.release("v3.0.0", true, false, catalogAgentAMD64, catalogAgentARM64, catalogChecksums),
		fixture.release("v2.5.0", false, false, catalogAgentAMD64, catalogChecksums),
		fixture.release("v2.6.0", false, false, catalogAgentAMD64, catalogAgentAMD64, catalogChecksums),
		fixture.release("v2.7.0", false, false, catalogAgentAMD64),
	}
	for len(page1) < 100 {
		page1 = append(page1, fixture.release(fmt.Sprintf("v0.0.%d", len(page1)+1), false, false, catalogAgentAMD64, catalogChecksums))
	}
	page2 := []map[string]any{
		fixture.release("v3.5.0", false, false, catalogAgentAMD64, catalogAgentARM64, catalogChecksums),
		fixture.release("v9.9.9", false, false, catalogServerAMD64, catalogChecksums),
	}

	var mu sync.Mutex
	requests := map[string]int{}
	client := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		mu.Lock()
		requests[req.URL.String()]++
		mu.Unlock()
		switch req.URL.String() {
		case releasesURL(1):
			return response(http.StatusOK, mustJSON(t, page1)), nil
		case releasesURL(2):
			return response(http.StatusOK, mustJSON(t, page2)), nil
		default:
			return nil, fmt.Errorf("unexpected URL %s", req.URL)
		}
	})

	catalog, err := FetchCatalogWithClient(context.Background(), client)
	if err != nil {
		t.Fatalf("FetchCatalogWithClient() error = %v", err)
	}

	tests := []struct {
		name      string
		component Component
		current   string
		goos      string
		goarch    string
		want      []string
	}{
		{"agent amd64", ComponentAgent, "1.0.0", "linux", "amd64", []string{"v3.5.0", "v2.5.0", "v2.0.0", "v1.5.0"}},
		{"agent arm64", ComponentAgent, "1.0.0", "linux", "arm64", []string{"v3.5.0", "v1.5.0"}},
		{"server amd64", ComponentServer, "1.0.0", "linux", "amd64", []string{"v9.9.9"}},
		{"already latest", ComponentAgent, "3.5.0", "linux", "amd64", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := catalog.AvailableFor(tt.component, tt.current, tt.goos, tt.goarch)
			if err != nil {
				t.Fatalf("AvailableFor() error = %v", err)
			}
			if fmt.Sprint(got) != fmt.Sprint(tt.want) {
				t.Fatalf("AvailableFor() = %v, want %v", got, tt.want)
			}
		})
	}

	if got := requests[releasesURL(1)]; got != 1 {
		t.Fatalf("page 1 requests = %d, want 1", got)
	}
	if got := requests[releasesURL(2)]; got != 1 {
		t.Fatalf("page 2 requests = %d, want 1", got)
	}
	if len(requests) != 2 {
		t.Fatalf("catalog requests = %v, want only pages 1 and 2", requests)
	}
}

func TestCatalogValidatesTargetBeforeFiltering(t *testing.T) {
	fixture := &catalogFixture{}
	body := mustJSON(t, []map[string]any{
		fixture.release("v2.0.0", false, false, catalogAgentAMD64, catalogChecksums),
	})
	client := roundTripFunc(func(*http.Request) (*http.Response, error) {
		return response(http.StatusOK, body), nil
	})
	catalog, err := FetchCatalogWithClient(context.Background(), client)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := catalog.AvailableFor(ComponentAgent, "1.0.0", "darwin", "amd64"); err == nil {
		t.Fatal("AvailableFor() accepted an unsupported platform")
	}
	if _, err := catalog.AvailableFor(ComponentAgent, "dev", "linux", "amd64"); err == nil {
		t.Fatal("AvailableFor() accepted a non-SemVer current version")
	}
	if _, err := catalog.AvailableFor(Component("other"), "1.0.0", "linux", "amd64"); err == nil {
		t.Fatal("AvailableFor() accepted an unsupported component")
	}
}

func TestCatalogConcurrentFilteringIsRaceFree(t *testing.T) {
	fixture := &catalogFixture{}
	body := mustJSON(t, []map[string]any{
		fixture.release("v2.0.0", false, false, catalogAgentAMD64, catalogAgentARM64, catalogChecksums),
	})
	client := roundTripFunc(func(*http.Request) (*http.Response, error) {
		return response(http.StatusOK, body), nil
	})
	catalog, err := FetchCatalogWithClient(context.Background(), client)
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		goarch := "amd64"
		if i%2 == 1 {
			goarch = "arm64"
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			versions, err := catalog.AvailableFor(ComponentAgent, "1.0.0", "linux", goarch)
			if err != nil || len(versions) != 1 || versions[0] != "v2.0.0" {
				t.Errorf("AvailableFor(%s) = %v, %v", goarch, versions, err)
			}
		}()
	}
	wg.Wait()
}

func TestFetchCatalogRejectsPaginationOverflow(t *testing.T) {
	fixture := &catalogFixture{}
	page := make([]map[string]any, 100)
	for i := range page {
		page[i] = fixture.release(fmt.Sprintf("v0.0.%d", i+1), false, false)
	}
	body := mustJSON(t, page)
	requests := 0
	client := roundTripFunc(func(*http.Request) (*http.Response, error) {
		requests++
		return response(http.StatusOK, body), nil
	})
	if _, err := FetchCatalogWithClient(context.Background(), client); err == nil || !strings.Contains(err.Error(), "pagination exceeds") {
		t.Fatalf("FetchCatalogWithClient() error = %v, want pagination error", err)
	}
	if requests != maxPages {
		t.Fatalf("requests = %d, want %d", requests, maxPages)
	}
}

func TestFetchCatalogPropagatesHTTPFailure(t *testing.T) {
	client := roundTripFunc(func(*http.Request) (*http.Response, error) {
		return response(http.StatusInternalServerError, "boom"), nil
	})
	if _, err := FetchCatalogWithClient(context.Background(), client); err == nil {
		t.Fatal("FetchCatalogWithClient() accepted a failed response")
	}
}

func TestFetchCatalogHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	client := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		<-req.Context().Done()
		return nil, req.Context().Err()
	})
	if _, err := FetchCatalogWithClient(ctx, client); err == nil {
		t.Fatal("FetchCatalogWithClient() ignored a canceled context")
	}
}
