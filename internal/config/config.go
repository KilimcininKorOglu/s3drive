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

	MaxObjectBytes    int64
	DailyUploadBytes  int64
	MaxUploadsPerAcct int
	DiskReserveBytes  int64
	MaxUIBodyBytes    int64
	ShutdownTimeout   time.Duration
	LoginMaxFailures  int
	LoginWindow       time.Duration
	LoginLockout      time.Duration

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

		MaxObjectBytes:    5 * (1 << 40),
		DailyUploadBytes:  750 * (1 << 30),
		MaxUploadsPerAcct: 4,
		DiskReserveBytes:  1 << 30,
		MaxUIBodyBytes:    1 << 30,
		ShutdownTimeout:   5 * time.Minute,
		LoginMaxFailures:  5,
		LoginWindow:       15 * time.Minute,
		LoginLockout:      15 * time.Minute,
	}

	if c.MaxObjectBytes, err = envBytes("S3DRIVE_MAX_OBJECT_BYTES", c.MaxObjectBytes); err != nil {
		return c, err
	}
	if c.DailyUploadBytes, err = envBytes("S3DRIVE_DAILY_UPLOAD_BYTES", c.DailyUploadBytes); err != nil {
		return c, err
	}
	if c.MaxUploadsPerAcct, err = envInt("S3DRIVE_MAX_CONCURRENT_UPLOADS", c.MaxUploadsPerAcct); err != nil {
		return c, err
	}
	if c.DiskReserveBytes, err = envBytes("S3DRIVE_DISK_RESERVE_BYTES", c.DiskReserveBytes); err != nil {
		return c, err
	}
	if c.MaxUIBodyBytes, err = envBytes("S3DRIVE_MAX_UI_BODY_BYTES", c.MaxUIBodyBytes); err != nil {
		return c, err
	}
	if c.ShutdownTimeout, err = envDuration("S3DRIVE_SHUTDOWN_TIMEOUT", c.ShutdownTimeout); err != nil {
		return c, err
	}
	if c.LoginMaxFailures, err = envInt("S3DRIVE_LOGIN_MAX_FAILURES", c.LoginMaxFailures); err != nil {
		return c, err
	}
	if c.LoginWindow, err = envDuration("S3DRIVE_LOGIN_WINDOW", c.LoginWindow); err != nil {
		return c, err
	}
	if c.LoginLockout, err = envDuration("S3DRIVE_LOGIN_LOCKOUT", c.LoginLockout); err != nil {
		return c, err
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

func envInt(key string, def int) (int, error) {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return def, fmt.Errorf("%s must be a non-negative integer", key)
	}
	return n, nil
}

func envBytes(key string, def int64) (int64, error) {
	v := strings.ToUpper(strings.TrimSpace(os.Getenv(key)))
	if v == "" {
		return def, nil
	}
	mult := int64(1)
	for suffix, m := range map[string]int64{
		"KIB": 1 << 10, "MIB": 1 << 20, "GIB": 1 << 30, "TIB": 1 << 40,
		"KB": 1000, "MB": 1000 * 1000, "GB": 1000 * 1000 * 1000, "TB": 1000 * 1000 * 1000 * 1000,
	} {
		if strings.HasSuffix(v, suffix) {
			mult = m
			v = strings.TrimSuffix(v, suffix)
			break
		}
	}
	n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
	if err != nil || n < 0 {
		return def, fmt.Errorf("%s must be a byte count (for example 5GiB)", key)
	}
	return n * mult, nil
}

func envDuration(key string, def time.Duration) (time.Duration, error) {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < 0 {
		return def, fmt.Errorf("%s must be a duration (for example 5m)", key)
	}
	return d, nil
}
