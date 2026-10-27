package server

import (
	"crypto/sha256"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/Flyinsky2004/oh-my-acme/internal/domain"
)

func TestCertificateRowConfirmsIssueAndDeleteWithDomain(t *testing.T) {
	tmpl, err := parseWebTemplates()
	if err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	cert := &domain.Certificate{ID: "cert1", RootDomain: "example.com", Current: &domain.CertificateVersion{ID: "v1"}, TargetAgents: []string{"agent1"}}
	if err := tmpl.ExecuteTemplate(&out, "certificate-row", makeCertificateRow(cert)); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"issue", "delete"} {
		button := regexp.MustCompile(`<button[^>]+hx-post="/certificates/cert1/` + action + `"[^>]*>`).FindString(out.String())
		if !strings.Contains(button, `hx-confirm="警告：`) || !strings.Contains(button, "example.com") {
			t.Errorf("%s button lacks a named warning: %s", action, button)
		}
	}
}

func TestRenderedWebShellsVersionAssetsByContent(t *testing.T) {
	web, err := NewWeb(nil)
	if err != nil {
		t.Fatal(err)
	}
	assetRef := regexp.MustCompile(`(?:href|src)="(/static/[^"]+)"`)
	for _, name := range []string{"layout", "login"} {
		t.Run(name, func(t *testing.T) {
			var out strings.Builder
			if err := web.tmpl.ExecuteTemplate(&out, name, map[string]any{}); err != nil {
				t.Fatal(err)
			}
			refs := assetRef.FindAllStringSubmatch(out.String(), -1)
			if len(refs) < 2 {
				t.Fatal("expected local stylesheet and script assets")
			}
			for _, ref := range refs {
				u, err := url.Parse(ref[1])
				if err != nil {
					t.Fatal(err)
				}
				data, err := staticFS.ReadFile("web" + u.Path)
				if err != nil {
					t.Fatal(err)
				}
				sum := sha256.Sum256(data)
				if got, want := u.Query().Get("v"), fmt.Sprintf("%x", sum[:8]); got != want {
					t.Errorf("asset %s version = %q, want content hash %q", u.Path, got, want)
				}
			}
		})
	}
}

func TestStaticAssetsRequireRevalidation(t *testing.T) {
	for _, path := range []string{"/static/app.js", "/static/app.css", "/static/app.js?v=upgrade"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rw := httptest.NewRecorder()
		(&Web{}).Handler().ServeHTTP(rw, req)
		if rw.Code != http.StatusOK {
			t.Fatalf("GET %s: status %d", path, rw.Code)
		}
		if got := rw.Header().Get("Cache-Control"); got != "no-cache" {
			t.Errorf("GET %s: Cache-Control = %q, want no-cache", path, got)
		}
	}
}

func TestWebTemplatesParse(t *testing.T) {
	tmpl, err := parseWebTemplates()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"layout", "login", "dashboard", "certificates", "certificate-row", "certnew",
		"certificate-log", "certificate-log-content", "credentials", "credform",
		"agents", "settings", "icon-dashboard",
	} {
		if tmpl.Lookup(name) == nil {
			t.Errorf("template %q is not defined", name)
		}
	}
}

func TestWebShellsUseOnlyLocalStaticAssets(t *testing.T) {
	assetRef := regexp.MustCompile(`(?:href|src)="([^"]+)"`)
	for _, name := range []string{"layout.html", "login.html"} {
		body, err := fs.ReadFile(templatesFS, "web/templates/"+name)
		if err != nil {
			t.Fatal(err)
		}
		for _, match := range assetRef.FindAllStringSubmatch(string(body), -1) {
			ref := match[1]
			if strings.HasPrefix(ref, "http://") || strings.HasPrefix(ref, "https://") || strings.HasPrefix(ref, "//") {
				t.Errorf("%s references remote asset %q", name, ref)
			}
		}
		for _, local := range []string{`{{assetURL "app.css"}}`, `{{assetURL "htmx.min.js"}}`} {
			if !strings.Contains(string(body), local) {
				t.Errorf("%s does not reference %s", name, local)
			}
		}
	}
}

func TestEmbeddedWebAssetsAreNonEmpty(t *testing.T) {
	for _, name := range []string{"app.css", "htmx.min.js"} {
		body, err := fs.ReadFile(staticFS, "web/static/"+name)
		if err != nil {
			t.Fatal(err)
		}
		if len(body) == 0 {
			t.Errorf("embedded asset %s is empty", name)
		}
	}
}

func TestStaticCSSHandler(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/static/app.css", nil)
	rw := httptest.NewRecorder()
	(&Web{}).Handler().ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rw.Code, http.StatusOK)
	}
	if got := rw.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/css") {
		t.Fatalf("Content-Type = %q, want text/css", got)
	}
	if rw.Body.Len() == 0 {
		t.Fatal("CSS response body is empty")
	}
}

func TestCompiledCSSHasNoRemoteDependencies(t *testing.T) {
	body, err := fs.ReadFile(staticFS, "web/static/app.css")
	if err != nil {
		t.Fatal(err)
	}
	css := strings.ToLower(string(body))
	for _, forbidden := range []string{"@import", "url(http://", "url(https://", "url(//"} {
		if strings.Contains(css, forbidden) {
			t.Errorf("compiled CSS contains remote-capable dependency %q", forbidden)
		}
	}
}

func TestCompiledCSSKeepsCodeSelectionReadable(t *testing.T) {
	body, err := fs.ReadFile(staticFS, "web/static/app.css")
	if err != nil {
		t.Fatal(err)
	}
	css := string(body)
	for _, want := range []string{"--code-selection-ink:", "--code-selection-bg:", "code::selection", "pre::selection"} {
		if !strings.Contains(css, want) {
			t.Errorf("compiled CSS does not contain %q", want)
		}
	}
}
