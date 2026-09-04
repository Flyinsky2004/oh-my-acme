package server

import (
	"html/template"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func TestWebTemplatesParse(t *testing.T) {
	tmpl, err := template.ParseFS(templatesFS, "web/templates/*.html")
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
		for _, local := range []string{`href="/static/app.css"`, `src="/static/htmx.min.js"`} {
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
