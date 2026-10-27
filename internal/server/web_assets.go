package server

import (
	"crypto/sha256"
	"embed"
	"fmt"
	"html/template"
)

//go:embed web/templates/*.html
var templatesFS embed.FS

//go:embed web/static/*
var staticFS embed.FS

// Content versions keep upgraded HTML from loading scripts or styles cached
// from an older server, including when Version is still "dev".
func staticAssetURL(name string) (string, error) {
	data, err := staticFS.ReadFile("web/static/" + name)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return fmt.Sprintf("/static/%s?v=%x", name, sum[:8]), nil
}

func parseWebTemplates() (*template.Template, error) {
	return template.New("").Funcs(template.FuncMap{"assetURL": staticAssetURL}).ParseFS(templatesFS, "web/templates/*.html")
}
