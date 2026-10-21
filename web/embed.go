package web

import "embed"

// FS holds the templates and static assets that are compiled into the binary.
//
//go:embed templates/*.html static/*
var FS embed.FS
