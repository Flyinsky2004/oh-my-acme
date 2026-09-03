// Package updater securely updates oh-my-acme binaries from official GitHub releases.
package updater

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	repository = "Flyinsky2004/oh-my-acme"
	apiBase    = "https://api.github.com/repos/" + repository
	userAgent  = "oh-my-acme-updater/1.0"

	maxPages               = 3
	maxReleaseResponseSize = 1 << 20
	maxChecksumsSize       = 1 << 20
	maxArchiveSize         = 64 << 20
	maxBinarySize          = 32 << 20
	maxExpandedArchiveSize = maxBinarySize + (1 << 20)
)

// ErrNoUpdate indicates that no newer eligible release is available.
var ErrNoUpdate = errors.New("no eligible update")

// Component identifies an oh-my-acme binary that can be updated.
type Component string

const (
	ComponentServer Component = "server"
	ComponentAgent  Component = "agent"
)

// Client is the minimal HTTP dependency used by the updater.
type Client interface {
	Do(*http.Request) (*http.Response, error)
}

type platform struct {
	goos   string
	goarch string
}

type updater struct {
	client         Client
	executablePath string
	platform       platform
	syncDirectory  func(string) error
}

type replacementCompletedError struct {
	err error
}

func (e *replacementCompletedError) Error() string {
	return "replacement succeeded but directory sync failed: " + e.err.Error()
}

func (e *replacementCompletedError) Unwrap() error {
	return e.err
}

type release struct {
	tag       string
	version   semVersion
	archive   releaseAsset
	checksums releaseAsset
}

type githubRelease struct {
	TagName    string         `json:"tag_name"`
	Draft      bool           `json:"draft"`
	Prerelease bool           `json:"prerelease"`
	Assets     []releaseAsset `json:"assets"`
}

type releaseAsset struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
	Size int64  `json:"size"`
}

func newUpdater(client Client, executablePath string, target platform) *updater {
	return &updater{
		client:         client,
		executablePath: executablePath,
		platform:       target,
		syncDirectory:  syncDirectory,
	}
}

func newGitHubClient() *http.Client {
	return &http.Client{
		Timeout:       30 * time.Second,
		CheckRedirect: allowGitHubRedirect,
	}
}

func allowGitHubRedirect(request *http.Request, _ []*http.Request) error {
	host := strings.ToLower(strings.TrimSuffix(request.URL.Hostname(), "."))
	if request.URL.Scheme != "https" || !isGitHubHost(host) {
		return fmt.Errorf("refuse redirect to %q", request.URL.String())
	}
	return nil
}

func isGitHubHost(host string) bool {
	return host == "github.com" || strings.HasSuffix(host, ".github.com") || host == "githubusercontent.com" || strings.HasSuffix(host, ".githubusercontent.com")
}

// Available returns eligible releases newer than currentVersion for the
// current process platform, newest first.
func Available(ctx context.Context, component Component, currentVersion string) ([]string, error) {
	return AvailableFor(ctx, component, currentVersion, runtime.GOOS, runtime.GOARCH)
}

// AvailableFor returns eligible releases for a known target platform. It is
// used by the Server to filter options for a registered Agent; the Agent still
// revalidates against its own runtime before replacing itself.
func AvailableFor(ctx context.Context, component Component, currentVersion, goos, goarch string) ([]string, error) {
	u := newUpdater(newGitHubClient(), "", platform{goos: goos, goarch: goarch})
	releases, err := u.available(ctx, component, currentVersion)
	if err != nil {
		return nil, err
	}
	versions := make([]string, len(releases))
	for i, item := range releases {
		versions[i] = item.tag
	}
	return versions, nil
}

// Update installs the highest eligible release newer than currentVersion and returns its tag.
func Update(ctx context.Context, component Component, currentVersion string) (string, error) {
	executablePath, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("resolve executable path: %w", err)
	}
	u := newUpdater(newGitHubClient(), executablePath, platform{goos: runtime.GOOS, goarch: runtime.GOARCH})
	return u.update(ctx, component, currentVersion)
}

// UpdateTo installs one exact eligible target version. The repository, asset
// name, platform and executable path remain fixed inside this package.
func UpdateTo(ctx context.Context, component Component, currentVersion, targetVersion string) (string, error) {
	executablePath, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("resolve executable path: %w", err)
	}
	u := newUpdater(newGitHubClient(), executablePath, platform{goos: runtime.GOOS, goarch: runtime.GOARCH})
	return u.updateTo(ctx, component, currentVersion, targetVersion)
}

func (u *updater) update(ctx context.Context, component Component, currentVersion string) (string, error) {
	if u.executablePath == "" {
		return "", errors.New("empty executable path")
	}
	releases, err := u.available(ctx, component, currentVersion)
	if err != nil {
		return "", err
	}
	if len(releases) == 0 {
		return "", ErrNoUpdate
	}

	return u.installRelease(ctx, component, releases[0])
}

func (u *updater) updateTo(ctx context.Context, component Component, currentVersion, targetVersion string) (string, error) {
	if u.executablePath == "" {
		return "", errors.New("empty executable path")
	}
	targetParsed, err := parseSemVer(targetVersion)
	if err != nil || !targetParsed.stable() {
		return "", fmt.Errorf("target version %q is not a stable SemVer", targetVersion)
	}
	releases, err := u.available(ctx, component, currentVersion)
	if err != nil {
		return "", err
	}
	for _, candidate := range releases {
		if candidate.version.compare(targetParsed) == 0 {
			return u.installRelease(ctx, component, candidate)
		}
	}
	return "", fmt.Errorf("target version %q is not an eligible upgrade", targetVersion)
}

func (u *updater) installRelease(ctx context.Context, component Component, target release) (string, error) {
	manifest, err := u.downloadAsset(ctx, target.checksums.ID, maxChecksumsSize)
	if err != nil {
		return "", fmt.Errorf("download checksums for %s: %w", target.tag, err)
	}
	expectedDigest, err := checksumForAsset(manifest, target.archive.Name)
	if err != nil {
		return "", fmt.Errorf("read checksum manifest for %s: %w", target.tag, err)
	}
	archive, err := u.downloadAsset(ctx, target.archive.ID, maxArchiveSize)
	if err != nil {
		return "", fmt.Errorf("download archive for %s: %w", target.tag, err)
	}
	actualDigest := sha256.Sum256(archive)
	if !bytes.Equal(actualDigest[:], expectedDigest) {
		return "", fmt.Errorf("verify archive for %s: SHA-256 mismatch", target.tag)
	}
	binaryName, err := binaryName(component)
	if err != nil {
		return "", err
	}
	if err := u.installArchive(archive, binaryName); err != nil {
		var completed *replacementCompletedError
		if errors.As(err, &completed) {
			return target.tag, fmt.Errorf("install %s: %w", target.tag, err)
		}
		return "", fmt.Errorf("install %s: %w", target.tag, err)
	}
	return target.tag, nil
}

func (u *updater) available(ctx context.Context, component Component, currentVersion string) ([]release, error) {
	current, err := parseSemVer(currentVersion)
	if err != nil {
		return nil, fmt.Errorf("parse current version %q: SemVer 2.0.0 required", currentVersion)
	}
	archiveName, err := archiveName(component, u.platform)
	if err != nil {
		return nil, err
	}

	var eligible []release
	for page := 1; page <= maxPages; page++ {
		body, err := u.request(ctx, http.MethodGet, releasesURL(page), "", maxReleaseResponseSize)
		if err != nil {
			return nil, fmt.Errorf("list releases page %d: %w", page, err)
		}
		var listed []githubRelease
		if err := json.Unmarshal(body, &listed); err != nil {
			return nil, fmt.Errorf("decode releases page %d: %w", page, err)
		}
		for _, candidate := range listed {
			item, ok := candidate.eligible(archiveName, current)
			if ok {
				eligible = append(eligible, item)
			}
		}
		if len(listed) < 100 {
			break
		}
		if page == maxPages {
			return nil, fmt.Errorf("release pagination exceeds %d pages", maxPages)
		}
	}
	sort.Slice(eligible, func(i, j int) bool {
		return eligible[i].version.compare(eligible[j].version) > 0
	})
	return uniqueReleases(eligible), nil
}

func (r githubRelease) eligible(archiveName string, current semVersion) (release, bool) {
	if r.Draft || r.Prerelease {
		return release{}, false
	}
	version, err := parseSemVer(r.TagName)
	if err != nil || !version.stable() || version.compare(current) <= 0 {
		return release{}, false
	}
	archive, ok := uniqueAsset(r.Assets, archiveName)
	if !ok || archive.ID <= 0 || archive.Size < 0 || archive.Size > maxArchiveSize {
		return release{}, false
	}
	checksums, ok := uniqueAsset(r.Assets, "checksums.txt")
	if !ok || checksums.ID <= 0 || checksums.Size < 0 || checksums.Size > maxChecksumsSize {
		return release{}, false
	}
	return release{tag: r.TagName, version: version, archive: archive, checksums: checksums}, true
}

func uniqueReleases(releases []release) []release {
	if len(releases) < 2 {
		return releases
	}
	result := make([]release, 0, len(releases))
	for _, item := range releases {
		if len(result) == 0 || result[len(result)-1].version.compare(item.version) != 0 {
			result = append(result, item)
		}
	}
	return result
}

func uniqueAsset(assets []releaseAsset, name string) (releaseAsset, bool) {
	var found releaseAsset
	for _, asset := range assets {
		if asset.Name != name {
			continue
		}
		if found.Name != "" {
			return releaseAsset{}, false
		}
		found = asset
	}
	return found, found.Name != ""
}

func (u *updater) downloadAsset(ctx context.Context, id int64, limit int64) ([]byte, error) {
	return u.request(ctx, http.MethodGet, assetURL(id), "application/octet-stream", limit)
}

func (u *updater) request(ctx context.Context, method, rawURL, accept string, limit int64) ([]byte, error) {
	if u.client == nil {
		return nil, errors.New("nil HTTP client")
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("User-Agent", userAgent)
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	resp, err := u.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("perform request: %w", err)
	}
	if resp == nil || resp.Body == nil {
		return nil, errors.New("HTTP client returned empty response")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected HTTP status %d", resp.StatusCode)
	}
	if resp.ContentLength > limit {
		return nil, fmt.Errorf("response exceeds %d byte limit", limit)
	}
	body, err := readLimited(resp.Body, limit)
	if err != nil {
		return nil, err
	}
	return body, nil
}

func readLimited(reader io.Reader, limit int64) ([]byte, error) {
	if limit < 0 {
		return nil, errors.New("negative read limit")
	}
	body, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("response exceeds %d byte limit", limit)
	}
	return body, nil
}

func checksumForAsset(manifest []byte, name string) ([]byte, error) {
	var digest []byte
	for _, line := range strings.Split(string(manifest), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || fields[1] != name {
			continue
		}
		decoded, err := hex.DecodeString(fields[0])
		if err != nil || len(decoded) != sha256.Size {
			return nil, fmt.Errorf("invalid SHA-256 for %q", name)
		}
		if digest != nil {
			return nil, fmt.Errorf("multiple checksums for %q", name)
		}
		digest = decoded
	}
	if digest == nil {
		return nil, fmt.Errorf("checksum for %q not found", name)
	}
	return digest, nil
}

func (u *updater) installArchive(archive []byte, expectedBinary string) error {
	binary, err := extractArchive(archive, expectedBinary)
	if err != nil {
		return err
	}
	directory := filepath.Dir(u.executablePath)
	file, err := os.CreateTemp(directory, ".oh-my-acme-update-*")
	if err != nil {
		return fmt.Errorf("create staging file: %w", err)
	}
	temporaryPath := file.Name()
	closed := false
	renamed := false
	defer func() {
		if !closed {
			_ = file.Close()
		}
		if !renamed {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := file.Chmod(0o755); err != nil {
		return fmt.Errorf("set staging mode: %w", err)
	}
	if err := writeAll(file, binary); err != nil {
		return fmt.Errorf("write staging binary: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync staging binary: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close staging binary: %w", err)
	}
	closed = true
	if err := os.Rename(temporaryPath, u.executablePath); err != nil {
		return fmt.Errorf("replace executable: %w", err)
	}
	renamed = true
	if err := u.syncDirectory(directory); err != nil {
		return &replacementCompletedError{err: fmt.Errorf("sync executable directory: %w", err)}
	}
	return nil
}

func syncDirectory(directory string) error {
	if runtime.GOOS != "linux" {
		return nil
	}
	file, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := writer.Write(data)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func extractArchive(archive []byte, expectedBinary string) ([]byte, error) {
	if expectedBinary == "" || expectedBinary != filepath.Base(expectedBinary) || strings.Contains(expectedBinary, "\\") {
		return nil, errors.New("invalid expected binary name")
	}
	gzipReader, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, fmt.Errorf("open gzip archive: %w", err)
	}
	expanded := &io.LimitedReader{R: gzipReader, N: maxExpandedArchiveSize + 1}
	tarReader := tar.NewReader(expanded)
	var binary []byte
	entries := 0
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read tar archive: %w", err)
		}
		entries++
		if entries > 1 {
			return nil, errors.New("archive contains extra entries")
		}
		if !safeArchiveName(header.Name) || header.Name != expectedBinary {
			return nil, fmt.Errorf("unexpected archive path %q", header.Name)
		}
		if header.Typeflag != tar.TypeReg || header.Size <= 0 || header.Size > maxBinarySize {
			return nil, fmt.Errorf("invalid binary entry %q", header.Name)
		}
		content, err := readLimited(tarReader, maxBinarySize)
		if err != nil {
			return nil, fmt.Errorf("read binary entry: %w", err)
		}
		if int64(len(content)) != header.Size {
			return nil, fmt.Errorf("binary entry size mismatch: got %d, want %d", len(content), header.Size)
		}
		binary = content
	}
	if entries != 1 {
		return nil, errors.New("archive does not contain a binary")
	}
	if _, err := io.Copy(io.Discard, expanded); err != nil {
		return nil, fmt.Errorf("read archive trailer: %w", err)
	}
	if expanded.N == 0 {
		return nil, fmt.Errorf("archive exceeds %d byte expanded limit", maxExpandedArchiveSize)
	}
	if err := gzipReader.Close(); err != nil {
		return nil, fmt.Errorf("close gzip archive: %w", err)
	}
	return binary, nil
}

func safeArchiveName(name string) bool {
	return name != "" && !strings.Contains(name, "\\") && !strings.HasPrefix(name, "/") && name == filepath.Base(name)
}

func archiveName(component Component, target platform) (string, error) {
	if target.goos != "linux" || (target.goarch != "amd64" && target.goarch != "arm64") {
		return "", fmt.Errorf("unsupported platform %s/%s", target.goos, target.goarch)
	}
	binary, err := binaryName(component)
	if err != nil {
		return "", err
	}
	return binary + "_linux_" + target.goarch + ".tar.gz", nil
}

func binaryName(component Component) (string, error) {
	switch component {
	case ComponentServer:
		return "oh-my-acme-server", nil
	case ComponentAgent:
		return "oh-my-acme-agent", nil
	default:
		return "", fmt.Errorf("unsupported component %q", component)
	}
}

func releasesURL(page int) string {
	return apiBase + "/releases?per_page=100&page=" + strconv.Itoa(page)
}

func assetURL(id int64) string {
	return apiBase + "/releases/assets/" + strconv.FormatInt(id, 10)
}
