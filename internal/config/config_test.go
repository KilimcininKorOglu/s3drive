package config

import "testing"

func TestLoadCustomLimits(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("S3DRIVE_DATA_DIR", dir)
	t.Setenv("S3DRIVE_MAX_OBJECT_BYTES", "2GiB")
	t.Setenv("S3DRIVE_DAILY_UPLOAD_BYTES", "100GB")
	t.Setenv("S3DRIVE_MAX_CONCURRENT_UPLOADS", "3")
	t.Setenv("S3DRIVE_LOGIN_MAX_FAILURES", "7")
	t.Setenv("S3DRIVE_SHUTDOWN_TIMEOUT", "90s")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MaxObjectBytes != 2<<30 {
		t.Fatalf("MaxObjectBytes = %d", cfg.MaxObjectBytes)
	}
	if cfg.DailyUploadBytes != 100*1000*1000*1000 {
		t.Fatalf("DailyUploadBytes = %d", cfg.DailyUploadBytes)
	}
	if cfg.MaxUploadsPerAcct != 3 || cfg.LoginMaxFailures != 7 {
		t.Fatalf("limits = %+v", cfg)
	}
	if cfg.ShutdownTimeout.Seconds() != 90 {
		t.Fatalf("ShutdownTimeout = %v", cfg.ShutdownTimeout)
	}
}

func TestLoadRejectsBadValues(t *testing.T) {
	t.Setenv("S3DRIVE_DATA_DIR", t.TempDir())
	t.Setenv("S3DRIVE_MAX_OBJECT_BYTES", "lots")
	if _, err := Load(); err == nil {
		t.Fatal("invalid byte count accepted")
	}
}
