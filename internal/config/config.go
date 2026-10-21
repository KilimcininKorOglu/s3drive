// Package config loads s3drive runtime configuration from the environment.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Version is stamped into the UI, the S3 Server header and the health endpoint.
// It can be overridden at build time with -X s3drive/internal/config.Version.
var Version = "0.1.0"

const (
	DefaultS3Addr = ":9000"
	DefaultUIAddr = ":8080"
)

// Config is the process-wide configuration. Values that can be changed at
// runtime (OAuth client, region, pool name, CORS) live in the settings table
// and are read from the store, not from here.
type Config struct {
	DataDir     string
	S3Addr      string
	UIAddr      string
	PublicURL   string
	PublicS3URL string
	MasterKey   string
	UIPassword  string
	LogLevel    string
	SpoolDir    string
	SessionTTL  time.Duration

	// TrustProxy makes the UI honour X-Forwarded-* headers. Enable it only
	// behind a reverse proxy you control.
	TrustProxy bool
}

// Load reads configuration from S3DRIVE_* environment variables.
func Load() (Config, error) {
	cwd, err := os.Getwd()
	if err != nil {
		cwd = "."
	}

	c := Config{
		DataDir:     env("S3DRIVE_DATA_DIR", filepath.Join(cwd, "data")),
		S3Addr:      env("S3DRIVE_S3_ADDR", DefaultS3Addr),
		UIAddr:      env("S3DRIVE_UI_ADDR", DefaultUIAddr),
		PublicURL:   strings.TrimRight(env("S3DRIVE_PUBLIC_URL", "http://localhost:8080"), "/"),
		PublicS3URL: strings.TrimRight(strings.TrimSpace(os.Getenv("S3DRIVE_PUBLIC_S3_URL")), "/"),
		MasterKey:   os.Getenv("S3DRIVE_MASTER_KEY"),
		UIPassword:  os.Getenv("S3DRIVE_UI_PASSWORD"),
		LogLevel:    env("S3DRIVE_LOG_LEVEL", "info"),
		SessionTTL:  12 * time.Hour,
	}

	if v := os.Getenv("S3DRIVE_SPOOL_DIR"); v != "" {
		c.SpoolDir = v
	} else {
		c.SpoolDir = filepath.Join(c.DataDir, "tmp")
	}
	if v := os.Getenv("S3DRIVE_TRUST_PROXY"); v != "" {
		c.TrustProxy, err = strconv.ParseBool(v)
		if err != nil {
			return c, fmt.Errorf("S3DRIVE_TRUST_PROXY: %w", err)
		}
	}

	abs, err := filepath.Abs(c.DataDir)
	if err != nil {
		return c, fmt.Errorf("resolve data dir: %w", err)
	}
	c.DataDir = abs
	if err := os.MkdirAll(c.DataDir, 0o700); err != nil {
		return c, fmt.Errorf("create data dir: %w", err)
	}
	if err := os.MkdirAll(c.SpoolDir, 0o700); err != nil {
		return c, fmt.Errorf("create spool dir: %w", err)
	}
	return c, nil
}

func env(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}
