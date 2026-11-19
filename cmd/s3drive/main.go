// Command s3drive exposes Google Drive as S3-compatible storage.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
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
	defer closeLogged(st, "database", logger)

	s3srv, ui, err := newHandlers(cfg, st, logger)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pruneCtx, cancelPrune := context.WithCancel(context.Background())
	defer cancelPrune()
	startMaintenance(pruneCtx, st, cfg.SpoolDir, logger)

	s3ln, uiLn, err := listenBoth(&cfg)
	if err != nil {
		return err
	}
	warnConfig(&cfg,uiLn.Addr().String(), logger)
	logger.Info("s3drive starting", "version", config.Version,
		"s3", s3ln.Addr().String(), "ui", uiLn.Addr().String(), "data", cfg.DataDir)

	s3HTTP, uiHTTP := newHTTPServer(cfg.S3Addr, s3srv), newHTTPServer(cfg.UIAddr, ui)
	errCh := make(chan error, 2)
	logger.Info("s3 endpoint listening", "addr", s3ln.Addr().String())
	go serve(s3HTTP, s3ln, "s3 server", errCh)
	logger.Info("web console listening", "url", cfg.PublicURL)
	go serve(uiHTTP, uiLn, "ui server", errCh)

	var runErr error
	select {
	case <-ctx.Done():
		logger.Info("shutdown requested")
	case runErr = <-errCh:
		logger.Error("listener failed", "err", runErr)
	}
	shutdownAll(cfg.ShutdownTimeout, logger, map[string]*http.Server{"ui": uiHTTP, "s3": s3HTTP})
	return runErr
}

func newHandlers(cfg config.Config, st *store.Store, logger *slog.Logger) (http.Handler, http.Handler, error) {
	gc := google.NewClient(st)
	svc := drive.New(st, gc, cfg.SpoolDir, cfg.PublicURL, logger)
	svc.MaxObjectBytes = cfg.MaxObjectBytes
	svc.DailyUploadBytes = cfg.DailyUploadBytes
	svc.MaxUploadsPerAcct = cfg.MaxUploadsPerAcct
	svc.DiskReserveBytes = cfg.DiskReserveBytes
	auth := &s3.Authenticator{Store: st}
	s3srv := &s3.Server{Store: st, Svc: svc, Auth: auth, Log: logger, SpoolDir: cfg.SpoolDir}
	ui, err := webui.New(cfg, st, svc, gc, logger)
	if err != nil {
		return nil, nil, fmt.Errorf("web ui: %w", err)
	}
	return s3srv, ui, nil
}

// startMaintenance runs one startup pass, then one every six hours until
// ctx ends.
func startMaintenance(ctx context.Context, st *store.Store, spoolDir string, logger *slog.Logger) {
	maintenance(ctx, st, spoolDir, logger, true)
	go func() {
		t := time.NewTicker(6 * time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				maintenance(ctx, st, spoolDir, logger, false)
			}
		}
	}()
}

func listenBoth(cfg *config.Config) (s3ln, uiLn net.Listener, err error) {
	s3ln, err = net.Listen("tcp", cfg.S3Addr)
	if err != nil {
		return nil, nil, fmt.Errorf("listen s3 %s: %w", cfg.S3Addr, err)
	}
	uiLn, err = net.Listen("tcp", cfg.UIAddr)
	if err != nil {
		return nil, nil, errors.Join(fmt.Errorf("listen ui %s: %w", cfg.UIAddr, err), s3ln.Close())
	}
	return s3ln, uiLn, nil
}

func warnConfig(cfg *config.Config, uiAddr string, logger *slog.Logger) {
	if cfg.UIPassword == "" {
		logger.Warn("UI password is not set; anybody who can reach the console has full access",
			"addr", uiAddr, "hint", "set S3DRIVE_UI_PASSWORD")
	}
	if strings.Contains(cfg.PublicURL, "localhost") && !strings.Contains(uiAddr, "8080") {
		logger.Warn("public URL does not look like the UI listener; OAuth redirects may fail",
			"public_url", cfg.PublicURL, "ui_addr", uiAddr)
	}
}

func newHTTPServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       90 * time.Second,
	}
}

// serve reports any listener failure other than a graceful shutdown.
func serve(srv *http.Server, ln net.Listener, name string, errCh chan<- error) {
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		errCh <- fmt.Errorf("%s: %w", name, err)
	}
}

// shutdownAll drains every server concurrently within one shared timeout.
func shutdownAll(timeout time.Duration, logger *slog.Logger, servers map[string]*http.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var wg sync.WaitGroup
	for name, srv := range servers {
		wg.Go(func() {
			if err := srv.Shutdown(ctx); err != nil {
				logger.Warn(name+" shutdown", "err", err)
			}
		})
	}
	wg.Wait()
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
	if err := st.PruneUploadUsage(ctx, time.Now().AddDate(0, 0, -2)); err != nil {
		log.Warn("prune upload usage", "err", err)
	}
	if err := st.PruneDriveSessions(ctx, time.Now().AddDate(0, 0, -7)); err != nil {
		log.Warn("prune drive sessions", "err", err)
	}
	if n, err := s3.CleanupStaleUploads(ctx, st, spoolDir, time.Now().Add(-24*time.Hour)); err != nil {
		log.Warn("clean stale multipart uploads", "err", err)
	} else if n > 0 {
		log.Info("cleaned stale multipart uploads", "count", n)
	}
	if startup {
		cleanupSpool(spoolDir, 7*24*time.Hour, log)
	}
}

// cleanupSpool removes spool files older than maxAge. It works inside an
// os.Root so a symlink placed in the spool cannot redirect a removal outside.
func cleanupSpool(dir string, maxAge time.Duration, log *slog.Logger) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		log.Warn("clean spool", "err", err)
		return
	}
	defer closeLogged(root, "spool root", log)
	removed, err := removeStale(root, time.Now().Add(-maxAge), log)
	if err != nil {
		log.Warn("clean spool", "err", err)
		return
	}
	if removed > 0 {
		log.Info("cleaned stale spool files", "bytes", removed)
	}
}

func removeStale(root *os.Root, cutoff time.Time, log *slog.Logger) (int64, error) {
	var removed int64
	err := fs.WalkDir(root.FS(), ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			log.Warn("clean spool entry", "path", path, "err", err)
			return nil
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			log.Warn("clean spool entry", "path", path, "err", err)
			return nil
		}
		if info.ModTime().After(cutoff) {
			return nil
		}
		if err := root.Remove(path); err != nil {
			log.Warn("remove spool file", "path", path, "err", err)
			return nil
		}
		removed += info.Size()
		return nil
	})
	return removed, err
}

func closeLogged(c io.Closer, what string, log *slog.Logger) {
	if err := c.Close(); err != nil {
		log.Warn("close", "what", what, "err", err)
	}
}
