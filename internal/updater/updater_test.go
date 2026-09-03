package updater

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) Do(req *http.Request) (*http.Response, error) { return f(req) }

func response(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}
}

func TestAllowGitHubRedirect(t *testing.T) {
	tests := []struct {
		name    string
		rawURL  string
		wantErr bool
	}{
		{"github API", "https://api.github.com/repos/Flyinsky2004/oh-my-acme", false},
		{"release asset", "https://release-assets.githubusercontent.com/asset", false},
		{"objects host", "https://objects.githubusercontent.com/asset", false},
		{"wrong scheme", "http://github.com/asset", true},
		{"wrong host", "https://example.com/asset", true},
		{"suffix trap", "https://github.com.example.com/asset", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request, err := http.NewRequest(http.MethodGet, tt.rawURL, nil)
			if err != nil {
				t.Fatal(err)
			}
			err = allowGitHubRedirect(request, nil)
			if (err != nil) != tt.wantErr {
				t.Fatalf("allowGitHubRedirect() error = %v, wantErr=%v", err, tt.wantErr)
			}
		})
	}
}

func TestNewGitHubClientAndReplacementCompletedError(t *testing.T) {
	client := newGitHubClient()
	if client.Timeout <= 0 || client.CheckRedirect == nil {
		t.Fatalf("newGitHubClient() = %+v, want timeout and redirect policy", client)
	}
	cause := errors.New("directory sync failed")
	err := &replacementCompletedError{err: cause}
	if !errors.Is(err, cause) || !strings.Contains(err.Error(), "replacement succeeded") {
		t.Fatalf("replacementCompletedError = %v", err)
	}
}

type noProgressWriter struct{}

func (noProgressWriter) Write([]byte) (int, error) { return 0, nil }

func TestWriteAll(t *testing.T) {
	var output bytes.Buffer
	if err := writeAll(&output, []byte("binary")); err != nil {
		t.Fatal(err)
	}
	if output.String() != "binary" {
		t.Fatalf("output = %q", output.String())
	}
	if err := writeAll(noProgressWriter{}, []byte("binary")); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("writeAll() error = %v, want short write", err)
	}
}

func TestRequestRejectsInvalidResponses(t *testing.T) {
	tests := []struct {
		name   string
		client Client
	}{
		{"nil client", nil},
		{"request error", roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("network failed") })},
		{"nil response", roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, nil })},
		{"non-success status", roundTripFunc(func(*http.Request) (*http.Response, error) { return response(http.StatusForbidden, "denied"), nil })},
		{"oversized content length", roundTripFunc(func(*http.Request) (*http.Response, error) {
			result := response(http.StatusOK, "small")
			result.ContentLength = 6
			return result, nil
		})},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := newUpdater(tt.client, "", platform{})
			if _, err := u.request(context.Background(), http.MethodGet, releasesURL(1), "", 5); err == nil {
				t.Fatal("request() succeeded")
			}
		})
	}
}

func TestArchiveNameMatrix(t *testing.T) {
	tests := []struct {
		name      string
		component Component
		platform  platform
		want      string
		wantErr   bool
	}{
		{"server amd64", ComponentServer, platform{goos: "linux", goarch: "amd64"}, "oh-my-acme-server_linux_amd64.tar.gz", false},
		{"server arm64", ComponentServer, platform{goos: "linux", goarch: "arm64"}, "oh-my-acme-server_linux_arm64.tar.gz", false},
		{"agent amd64", ComponentAgent, platform{goos: "linux", goarch: "amd64"}, "oh-my-acme-agent_linux_amd64.tar.gz", false},
		{"agent arm64", ComponentAgent, platform{goos: "linux", goarch: "arm64"}, "oh-my-acme-agent_linux_arm64.tar.gz", false},
		{"invalid component", Component("other"), platform{goos: "linux", goarch: "amd64"}, "", true},
		{"invalid operating system", ComponentServer, platform{goos: "darwin", goarch: "amd64"}, "", true},
		{"invalid architecture", ComponentServer, platform{goos: "linux", goarch: "386"}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := archiveName(tt.component, tt.platform)
			if (err != nil) != tt.wantErr {
				t.Fatalf("archiveName() error = %v, wantErr=%v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("archiveName() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseSemVer(t *testing.T) {
	tests := []struct {
		name   string
		value  string
		valid  bool
		stable bool
	}{
		{"plain", "1.2.3", true, true},
		{"leading v", "v1.2.3", true, true},
		{"prerelease", "1.2.3-rc.1", true, false},
		{"build metadata", "1.2.3+build.7", true, true},
		{"large numeric identifiers", "184467440737095516160.2.3", true, true},
		{"leading zero", "01.2.3", false, false},
		{"missing patch", "1.2", false, false},
		{"prerelease leading zero", "1.2.3-01", false, false},
		{"empty identifier", "1.2.3-alpha..1", false, false},
		{"bad character", "1.2.3-a_1", false, false},
		{"tag prefix only", "v", false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			version, err := parseSemVer(tt.value)
			if tt.valid != (err == nil) {
				t.Fatalf("parseSemVer(%q) error = %v, want valid=%v", tt.value, err, tt.valid)
			}
			if err == nil && version.stable() != tt.stable {
				t.Fatalf("version.stable() = %v, want %v", version.stable(), tt.stable)
			}
		})
	}
}

func TestCompareSemVer(t *testing.T) {
	tests := []struct {
		left, right string
		want        int
	}{
		{"1.0.0", "1.0.0", 0},
		{"2.0.0", "1.9.9", 1},
		{"1.2.3", "1.2.4", -1},
		{"1.0.0-alpha", "1.0.0-alpha.1", -1},
		{"1.0.0-alpha.1", "1.0.0-alpha.beta", -1},
		{"1.0.0-beta", "1.0.0-beta.2", -1},
		{"1.0.0-rc.1", "1.0.0", -1},
		{"1.0.0+one", "1.0.0+two", 0},
		{"184467440737095516160.0.0", "184467440737095516159.999.999", 1},
		{"1.0.0-184467440737095516160", "1.0.0-184467440737095516161", -1},
	}
	for _, tt := range tests {
		t.Run(tt.left+"_"+tt.right, func(t *testing.T) {
			left, err := parseSemVer(tt.left)
			if err != nil {
				t.Fatal(err)
			}
			right, err := parseSemVer(tt.right)
			if err != nil {
				t.Fatal(err)
			}
			got := left.compare(right)
			if (got < 0 && tt.want < 0) || (got == 0 && tt.want == 0) || (got > 0 && tt.want > 0) {
				return
			}
			t.Fatalf("compare(%q, %q) = %d, want sign %d", tt.left, tt.right, got, tt.want)
		})
	}
}

func TestAvailableFiltersAndSortsReleases(t *testing.T) {
	archiveName := "oh-my-acme-server_linux_amd64.tar.gz"
	checksums := "checksums.txt"
	type asset struct {
		ID   int64  `json:"id"`
		Name string `json:"name"`
	}
	type releaseJSON struct {
		TagName    string  `json:"tag_name"`
		Draft      bool    `json:"draft"`
		Prerelease bool    `json:"prerelease"`
		Assets     []asset `json:"assets"`
	}
	validAssets := func(id int64) []asset {
		return []asset{{ID: id, Name: archiveName}, {ID: id + 1, Name: checksums}}
	}
	releases := []releaseJSON{
		{TagName: "v1.0.0", Assets: validAssets(1)},
		{TagName: "v1.5.0", Assets: validAssets(3)},
		{TagName: "v2.0.0-rc.1", Assets: validAssets(5)},
		{TagName: "v3.0.0", Prerelease: true, Assets: validAssets(7)},
		{TagName: "v3.0.0", Draft: true, Assets: validAssets(9)},
		{TagName: "broken", Assets: validAssets(11)},
		{TagName: "v2.0.0", Assets: []asset{{ID: 13, Name: archiveName}, {ID: 14, Name: archiveName}, {ID: 15, Name: checksums}}},
		{TagName: "v2.1.0", Assets: []asset{{ID: 16, Name: archiveName}}},
		{TagName: "v2.2.0", Assets: []asset{{ID: 17, Name: archiveName}, {ID: 18, Name: checksums}, {ID: 19, Name: checksums}}},
		{TagName: "v2.0.0", Assets: validAssets(20)},
	}
	jsonBody := mustJSON(t, releases)
	var requests []*http.Request
	client := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		requests = append(requests, req.Clone(req.Context()))
		if req.URL.String() != releasesURL(1) {
			t.Fatalf("URL = %s, want %s", req.URL, releasesURL(1))
		}
		if got := req.Header.Get("User-Agent"); got != userAgent {
			t.Fatalf("User-Agent = %q, want %q", got, userAgent)
		}
		return response(http.StatusOK, jsonBody), nil
	})
	u := newUpdater(client, filepath.Join(t.TempDir(), "binary"), platform{goos: "linux", goarch: "amd64"})
	available, err := u.available(context.Background(), ComponentServer, "1.0.0")
	if err != nil {
		t.Fatalf("available() error = %v", err)
	}
	got := make([]string, len(available))
	for i, item := range available {
		got[i] = item.tag
	}
	want := []string{"v2.0.0", "v1.5.0"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("available tags = %v, want %v", got, want)
	}
	if len(requests) != 1 {
		t.Fatalf("requests = %d, want 1", len(requests))
	}
}

func TestAvailableRejectsUnsupportedPlatformAndNoDowngrade(t *testing.T) {
	u := newUpdater(roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("client must not be called")
		return nil, nil
	}), "/tmp/binary", platform{goos: "darwin", goarch: "amd64"})
	if _, err := u.available(context.Background(), ComponentServer, "1.0.0"); err == nil {
		t.Fatal("available() succeeded for unsupported platform")
	}

	archiveName := "oh-my-acme-server_linux_amd64.tar.gz"
	body := mustJSON(t, []map[string]any{{
		"tag_name": "v1.0.0",
		"assets": []map[string]any{
			{"id": 1, "name": archiveName}, {"id": 2, "name": "checksums.txt"},
		},
	}})
	u = newUpdater(roundTripFunc(func(*http.Request) (*http.Response, error) {
		return response(http.StatusOK, body), nil
	}), "/tmp/binary", platform{goos: "linux", goarch: "amd64"})
	available, err := u.available(context.Background(), ComponentServer, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if len(available) != 0 {
		t.Fatalf("available = %v, want no equal/downgrade updates", available)
	}
}

func TestAvailableUpgradeEligibility(t *testing.T) {
	const archiveName = "oh-my-acme-server_linux_amd64.tar.gz"
	tests := []struct {
		name    string
		current string
		tag     string
		want    int
	}{
		{"prerelease current upgrades to stable", "v1.0.0-rc.1", "v1.0.0", 1},
		{"equal stable is excluded", "v1.0.0", "v1.0.0", 0},
		{"downgrade is excluded", "v2.0.0", "v1.0.0", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := mustJSON(t, []map[string]any{{
				"tag_name": tt.tag,
				"assets": []map[string]any{
					{"id": 1, "name": archiveName}, {"id": 2, "name": "checksums.txt"},
				},
			}})
			u := newUpdater(roundTripFunc(func(*http.Request) (*http.Response, error) {
				return response(http.StatusOK, body), nil
			}), filepath.Join(t.TempDir(), "binary"), platform{goos: "linux", goarch: "amd64"})
			available, err := u.available(context.Background(), ComponentServer, tt.current)
			if err != nil {
				t.Fatal(err)
			}
			if len(available) != tt.want {
				t.Fatalf("eligible releases = %d, want %d", len(available), tt.want)
			}
		})
	}
}

func TestChecksumForAsset(t *testing.T) {
	const name = "oh-my-acme-server_linux_amd64.tar.gz"
	valid := strings.Repeat("a", 64)
	tests := []struct {
		name    string
		content string
		wantErr bool
	}{
		{"exact match", valid + "  " + name + "\n", false},
		{"wrong filename", valid + "  other.tar.gz\n", true},
		{"invalid hex", strings.Repeat("g", 64) + "  " + name + "\n", true},
		{"duplicate", valid + "  " + name + "\n" + valid + "  " + name + "\n", true},
		{"prefix only is not exact", valid + "  " + name + ".bak\n", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := checksumForAsset([]byte(tt.content), name)
			if (err != nil) != tt.wantErr {
				t.Fatalf("checksumForAsset() error = %v, wantErr=%v", err, tt.wantErr)
			}
		})
	}
}

func TestExtractArchiveSafety(t *testing.T) {
	const binary = "oh-my-acme-server"
	large := bytes.Repeat([]byte{'x'}, maxBinarySize+1)
	tests := []struct {
		name    string
		entries []tarTestEntry
		want    string
		wantErr bool
	}{
		{"valid", []tarTestEntry{{name: binary, typeflag: tar.TypeReg, data: []byte("binary")}}, "binary", false},
		{"traversal", []tarTestEntry{{name: "../" + binary, typeflag: tar.TypeReg, data: []byte("binary")}}, "", true},
		{"absolute", []tarTestEntry{{name: "/" + binary, typeflag: tar.TypeReg, data: []byte("binary")}}, "", true},
		{"backslash", []tarTestEntry{{name: "dir\\" + binary, typeflag: tar.TypeReg, data: []byte("binary")}}, "", true},
		{"symlink", []tarTestEntry{{name: binary, typeflag: tar.TypeSymlink, linkname: "target"}}, "", true},
		{"hardlink", []tarTestEntry{{name: binary, typeflag: tar.TypeLink, linkname: "target"}}, "", true},
		{"duplicate", []tarTestEntry{{name: binary, typeflag: tar.TypeReg, data: []byte("one")}, {name: binary, typeflag: tar.TypeReg, data: []byte("two")}}, "", true},
		{"extra", []tarTestEntry{{name: binary, typeflag: tar.TypeReg, data: []byte("binary")}, {name: "README", typeflag: tar.TypeReg, data: []byte("extra")}}, "", true},
		{"oversized", []tarTestEntry{{name: binary, typeflag: tar.TypeReg, data: large}}, "", true},
		{"empty binary", []tarTestEntry{{name: binary, typeflag: tar.TypeReg}}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractArchive(makeArchive(t, tt.entries), binary)
			if (err != nil) != tt.wantErr {
				t.Fatalf("extractArchive() error = %v, wantErr=%v", err, tt.wantErr)
			}
			if string(got) != tt.want {
				t.Fatalf("extracted content = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractArchiveRejectsExpandedOverflow(t *testing.T) {
	archive := makeArchive(t, []tarTestEntry{{name: "oh-my-acme-server", typeflag: tar.TypeReg, data: []byte("binary")}})
	var trailingMember bytes.Buffer
	writer := gzip.NewWriter(&trailingMember)
	if _, err := writer.Write(bytes.Repeat([]byte{0}, maxExpandedArchiveSize+1)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	archive = append(archive, trailingMember.Bytes()...)
	if _, err := extractArchive(archive, "oh-my-acme-server"); err == nil {
		t.Fatal("extractArchive() accepted oversized expanded archive")
	}
}

func TestInstallArchiveReplacesDestinationAtomically(t *testing.T) {
	dir := t.TempDir()
	destination := filepath.Join(dir, "oh-my-acme-server")
	if err := os.WriteFile(destination, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	u := newUpdater(nil, destination, platform{goos: runtime.GOOS, goarch: runtime.GOARCH})
	valid := makeArchive(t, []tarTestEntry{{name: "oh-my-acme-server", typeflag: tar.TypeReg, data: []byte("new")}})
	if err := u.installArchive(valid, "oh-my-acme-server"); err != nil {
		t.Fatalf("installArchive() error = %v", err)
	}
	got, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new" {
		t.Fatalf("destination = %q, want new", got)
	}
	info, err := os.Stat(destination)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Fatalf("mode = %#o, want 0755", info.Mode().Perm())
	}

	invalid := makeArchive(t, []tarTestEntry{{name: "unexpected", typeflag: tar.TypeReg, data: []byte("bad")}})
	if err := u.installArchive(invalid, "oh-my-acme-server"); err == nil {
		t.Fatal("installArchive() succeeded for invalid archive")
	}
	got, err = os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new" {
		t.Fatalf("destination after failed install = %q, want preserved new", got)
	}
}

func TestInstallArchiveFailureCasesPreserveDestination(t *testing.T) {
	tests := []struct {
		name    string
		entries []tarTestEntry
	}{
		{"unexpected file", []tarTestEntry{{name: "unexpected", typeflag: tar.TypeReg, data: []byte("bad")}}},
		{"empty binary", []tarTestEntry{{name: "oh-my-acme-server", typeflag: tar.TypeReg}}},
		{"extra file", []tarTestEntry{{name: "oh-my-acme-server", typeflag: tar.TypeReg, data: []byte("new")}, {name: "extra", typeflag: tar.TypeReg, data: []byte("bad")}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			destination := filepath.Join(t.TempDir(), "oh-my-acme-server")
			if err := os.WriteFile(destination, []byte("old"), 0o700); err != nil {
				t.Fatal(err)
			}
			u := newUpdater(nil, destination, platform{goos: runtime.GOOS, goarch: runtime.GOARCH})
			if err := u.installArchive(makeArchive(t, tt.entries), "oh-my-acme-server"); err == nil {
				t.Fatal("installArchive() succeeded")
			}
			content, err := os.ReadFile(destination)
			if err != nil {
				t.Fatal(err)
			}
			if string(content) != "old" {
				t.Fatalf("destination = %q, want preserved old content", content)
			}
		})
	}
}

func TestInstallArchiveReportsPostRenameDirectorySyncFailure(t *testing.T) {
	destination := filepath.Join(t.TempDir(), "oh-my-acme-server")
	u := newUpdater(nil, destination, platform{goos: runtime.GOOS, goarch: runtime.GOARCH})
	u.syncDirectory = func(string) error { return errors.New("directory sync failed") }
	archive := makeArchive(t, []tarTestEntry{{name: "oh-my-acme-server", typeflag: tar.TypeReg, data: []byte("new")}})
	err := u.installArchive(archive, "oh-my-acme-server")
	var completed *replacementCompletedError
	if !errors.As(err, &completed) {
		t.Fatalf("installArchive() error = %v, want replacementCompletedError", err)
	}
	content, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "new" {
		t.Fatalf("destination = %q, want replacement content", content)
	}
}

func TestUpdateUsesFixedAssetURLsAndVerifiesChecksum(t *testing.T) {
	const archiveName = "oh-my-acme-server_linux_amd64.tar.gz"
	archive := makeArchive(t, []tarTestEntry{{name: "oh-my-acme-server", typeflag: tar.TypeReg, data: []byte("updated")}})
	digest := sha256Hex(archive)
	releaseBody := mustJSON(t, []map[string]any{{
		"tag_name": "v1.1.0",
		"assets": []map[string]any{
			{"id": 10, "name": archiveName}, {"id": 11, "name": "checksums.txt"},
		},
	}})
	var urls []string
	client := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		urls = append(urls, req.URL.String())
		if req.Header.Get("User-Agent") != userAgent {
			t.Fatalf("missing fixed User-Agent")
		}
		switch req.URL.String() {
		case releasesURL(1):
			return response(http.StatusOK, releaseBody), nil
		case assetURL(11):
			if req.Header.Get("Accept") != "application/octet-stream" {
				t.Fatalf("checksum asset Accept = %q", req.Header.Get("Accept"))
			}
			return response(http.StatusOK, digest+"  "+archiveName+"\n"), nil
		case assetURL(10):
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(archive)), Header: make(http.Header)}, nil
		default:
			t.Fatalf("unexpected URL %s", req.URL)
			return nil, nil
		}
	})
	destination := filepath.Join(t.TempDir(), "oh-my-acme-server")
	u := newUpdater(client, destination, platform{goos: "linux", goarch: "amd64"})
	version, err := u.update(context.Background(), ComponentServer, "1.0.0")
	if err != nil {
		t.Fatalf("update() error = %v", err)
	}
	if version != "v1.1.0" {
		t.Fatalf("version = %q, want v1.1.0", version)
	}
	if len(urls) != 3 {
		t.Fatalf("request count = %d, want 3", len(urls))
	}
}

func TestUpdateRejectsOversizedResponseAndChecksumMismatch(t *testing.T) {
	destination := filepath.Join(t.TempDir(), "binary")
	u := newUpdater(roundTripFunc(func(*http.Request) (*http.Response, error) {
		return response(http.StatusOK, strings.Repeat("x", maxReleaseResponseSize+1)), nil
	}), destination, platform{goos: "linux", goarch: "amd64"})
	if _, err := u.update(context.Background(), ComponentServer, "1.0.0"); err == nil {
		t.Fatal("update() accepted oversized release response")
	}

	archiveName := "oh-my-acme-server_linux_amd64.tar.gz"
	releaseBody := mustJSON(t, []map[string]any{{"tag_name": "v1.1.0", "assets": []map[string]any{{"id": 1, "name": archiveName}, {"id": 2, "name": "checksums.txt"}}}})
	u = newUpdater(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch req.URL.String() {
		case releasesURL(1):
			return response(http.StatusOK, releaseBody), nil
		case assetURL(2):
			return response(http.StatusOK, strings.Repeat("0", 64)+"  "+archiveName+"\n"), nil
		case assetURL(1):
			return response(http.StatusOK, "not-an-archive"), nil
		default:
			return nil, errors.New("unexpected URL")
		}
	}), destination, platform{goos: "linux", goarch: "amd64"})
	if _, err := u.update(context.Background(), ComponentServer, "1.0.0"); err == nil {
		t.Fatal("update() accepted checksum mismatch")
	}
	if _, err := os.Stat(destination); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("destination exists after failed update: %v", err)
	}
}

func TestReadLimitedRejectsNegativeLimit(t *testing.T) {
	if _, err := readLimited(strings.NewReader("data"), -1); err == nil {
		t.Fatal("readLimited() accepted negative limit")
	}
}

type tarTestEntry struct {
	name     string
	typeflag byte
	linkname string
	data     []byte
}

func makeArchive(t *testing.T, entries []tarTestEntry) []byte {
	t.Helper()
	var archive bytes.Buffer
	gzipWriter := gzip.NewWriter(&archive)
	tarWriter := tar.NewWriter(gzipWriter)
	for _, entry := range entries {
		header := &tar.Header{Name: entry.name, Typeflag: entry.typeflag, Linkname: entry.linkname, Mode: 0o755, Size: int64(len(entry.data))}
		if err := tarWriter.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if _, err := tarWriter.Write(entry.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	return archive.Bytes()
}

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func sha256Hex(value []byte) string {
	sum := sha256.Sum256(value)
	return fmt.Sprintf("%x", sum[:])
}
