package updater

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
)

// Catalog is an immutable snapshot of the official GitHub release listing.
// One Catalog is fetched per refresh and then filtered in memory for every
// component, version and platform, so a multi-Agent query performs one
// paginated download instead of one download per Agent.
type Catalog struct {
	releases []githubRelease
}

// FetchCatalog downloads the official release listing once. Pagination is
// bounded by maxPages and each page is requested at most once.
func FetchCatalog(ctx context.Context) (*Catalog, error) {
	return FetchCatalogWithClient(ctx, newGitHubClient())
}

// FetchCatalogWithClient is FetchCatalog with a caller-supplied minimal HTTP
// client. The repository, URLs and response limits stay fixed inside this
// package; only the transport is injected.
func FetchCatalogWithClient(ctx context.Context, client Client) (*Catalog, error) {
	u := newUpdater(client, "", platform{})
	return u.fetchCatalog(ctx)
}

func (u *updater) fetchCatalog(ctx context.Context) (*Catalog, error) {
	var listed []githubRelease
	for page := 1; page <= maxPages; page++ {
		body, err := u.request(ctx, http.MethodGet, releasesURL(page), "", maxReleaseResponseSize)
		if err != nil {
			return nil, fmt.Errorf("list releases page %d: %w", page, err)
		}
		var pageReleases []githubRelease
		if err := json.Unmarshal(body, &pageReleases); err != nil {
			return nil, fmt.Errorf("decode releases page %d: %w", page, err)
		}
		listed = append(listed, pageReleases...)
		if len(pageReleases) < 100 {
			break
		}
		if page == maxPages {
			return nil, fmt.Errorf("release pagination exceeds %d pages", maxPages)
		}
	}
	return &Catalog{releases: listed}, nil
}

// AvailableFor returns stable, compatible releases newer than currentVersion
// for one component and target platform. The Catalog is read-only, so the same
// snapshot can be filtered concurrently for different platforms without
// leaking one platform's result into another.
func (c *Catalog) AvailableFor(component Component, currentVersion, goos, goarch string) ([]string, error) {
	current, target, err := parseTarget(component, currentVersion, goos, goarch)
	if err != nil {
		return nil, err
	}
	releases, err := c.eligible(component, current, target)
	if err != nil {
		return nil, err
	}
	versions := make([]string, len(releases))
	for i, item := range releases {
		versions[i] = item.tag
	}
	return versions, nil
}

// eligible filters the shared listing for one already-validated target. It
// never mutates the Catalog.
func (c *Catalog) eligible(component Component, current semVersion, target platform) ([]release, error) {
	archiveName, err := archiveName(component, target)
	if err != nil {
		return nil, err
	}
	var eligible []release
	for _, candidate := range c.releases {
		if item, ok := candidate.eligible(archiveName, current); ok {
			eligible = append(eligible, item)
		}
	}
	sort.Slice(eligible, func(i, j int) bool {
		return eligible[i].version.compare(eligible[j].version) > 0
	})
	return uniqueReleases(eligible), nil
}

// parseTarget validates the current version and platform before any network
// access, preserving the error ordering of the previous per-call API.
func parseTarget(component Component, currentVersion, goos, goarch string) (semVersion, platform, error) {
	current, err := parseSemVer(currentVersion)
	if err != nil {
		return semVersion{}, platform{}, fmt.Errorf("parse current version %q: SemVer 2.0.0 required", currentVersion)
	}
	target := platform{goos: goos, goarch: goarch}
	if _, err := archiveName(component, target); err != nil {
		return semVersion{}, platform{}, err
	}
	return current, target, nil
}
