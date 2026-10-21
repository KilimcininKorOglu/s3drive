// Command s3drive exposes Google Drive as S3-compatible storage.
package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"s3drive/internal/config"
	"s3drive/internal/drive"
	"s3drive/internal/google"
	"s3drive/internal/s3"
	"s3drive/internal/secure"
	"s3drive/internal/store"
	"s3drive/internal/webui"
)

func main() {
	if err := run(); err != nil {
		slog.Error("s3drive stopped", "err", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	logger := newLogger(cfg.LogLevel)
	slog.SetDefault(logger)

	box, err := secure.New(cfg.DataDir, cfg.MasterKey)
	if err != nil {
		return fmt.Errorf("master key: %w", err)
	}
	st, err := store.Open(filepath.Join(cfg.DataDir, "s3drive.db"), box)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer st.Close()

	gc := google.NewClient(st)
	svc := drive.New(st, gc, cfg.SpoolDir, cfg.PublicURL, logger)
	auth := &s3.Authenticator{Store: st}
	s3srv := &s3.Server{Store: st, Svc: svc, Auth: auth, Log: logger, SpoolDir: cfg.SpoolDir}
	ui, err := webui.New(cfg, st, svc, gc, logger)
	if err != nil {
		return fmt.Errorf("web ui: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pruneCtx, cancelPrune := context.WithCancel(context.Background())
	defer cancelPrune()
	maintenance(pruneCtx, st, cfg.SpoolDir, logger, true)
	go func() {
		t := time.NewTicker(6 * time.Hour)
		defer t.Stop()
		for {
			select {
			case <-pruneCtx.Done():
				return
			case <-t.C:
				maintenance(pruneCtx, st, cfg.SpoolDir, logger, false)
			}
		}
	}()

	s3HTTP := &http.Server{
		Addr:              cfg.S3Addr,
		Handler:           s3srv,
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       90 * time.Second,
	}
	uiHTTP := &http.Server{
		Addr:              cfg.UIAddr,
		Handler:           ui,
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       90 * time.Second,
	}

	s3ln, err := net.Listen("tcp", cfg.S3Addr)
	if err != nil {
		return fmt.Errorf("listen s3 %s: %w", cfg.S3Addr, err)
	}
	uiLn, err := net.Listen("tcp", cfg.UIAddr)
	if err != nil {
		_ = s3ln.Close()
		return fmt.Errorf("listen ui %s: %w", cfg.UIAddr, err)
	}

	if cfg.UIPassword == "" {
		logger.Warn("UI password is not set; anybody who can reach the console has full access",
			"addr", uiLn.Addr().String(), "hint", "set S3DRIVE_UI_PASSWORD")
	}
	if strings.Contains(cfg.PublicURL, "localhost") && !strings.Contains(uiLn.Addr().String(), "8080") {
		logger.Warn("public URL does not look like the UI listener; OAuth redirects may fail",
			"public_url", cfg.PublicURL, "ui_addr", uiLn.Addr().String())
	}

	logger.Info("s3drive starting", "version", config.Version,
		"s3", s3ln.Addr().String(), "ui", uiLn.Addr().String(), "data", cfg.DataDir)

	errCh := make(chan error, 2)
	go func() {
		logger.Info("s3 endpoint listening", "addr", s3ln.Addr().String())
		if err := s3HTTP.Serve(s3ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("s3 server: %w", err)
		}
	}()
	go func() {
		logger.Info("web console listening", "url", cfg.PublicURL)
		if err := uiHTTP.Serve(uiLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("ui server: %w", err)
		}
	}()

	var runErr error
	select {
	case <-ctx.Done():
		logger.Info("shutdown requested")
	case runErr = <-errCh:
		logger.Error("listener failed", "err", runErr)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := uiHTTP.Shutdown(shutdownCtx); err != nil {
		logger.Warn("ui shutdown", "err", err)
	}
	if err := s3HTTP.Shutdown(shutdownCtx); err != nil {
		logger.Warn("s3 shutdown", "err", err)
	}
	return runErr
}

func newLogger(level string) *slog.Logger {
	var lv slog.Level
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		lv = slog.LevelDebug
	case "warn", "warning":
		lv = slog.LevelWarn
	case "error":
		lv = slog.LevelError
	default:
		lv = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: lv}))
}

// maintenance prunes old events, stale OAuth states and orphaned spool files.
func maintenance(ctx context.Context, st *store.Store, spoolDir string, log *slog.Logger, startup bool) {
	if err := st.PruneEvents(ctx, time.Now().AddDate(0, 0, -30)); err != nil {
		log.Warn("prune events", "err", err)
	}
	if err := st.PruneOAuthStates(ctx); err != nil {
		log.Warn("prune oauth states", "err", err)
	}
	if startup {
		cleanupSpool(spoolDir, 7*24*time.Hour, log)
	}
}

func cleanupSpool(dir string, maxAge time.Duration, log *slog.Logger) {
	cutoff := time.Now().Add(-maxAge)
	var removed int64
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() || path == dir {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.ModTime().After(cutoff) {
			return nil
		}
		if err := os.Remove(path); err == nil {
			removed += info.Size()
		}
		return nil
	})
	if err != nil {
		log.Warn("clean spool", "err", err)
		return
	}
	if removed > 0 {
		log.Info("cleaned stale spool files", "bytes", removed)
	}
}
