package server

import "embed"

//go:embed web/templates/*.html
var templatesFS embed.FS

//go:embed web/static/*
var staticFS embed.FS
