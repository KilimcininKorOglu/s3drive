package s3

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"time"

	"s3drive/internal/store"
)

// CleanupStaleUploads aborts multipart uploads that were never completed and
// removes their staged part files. It returns the number of uploads removed.
func CleanupStaleUploads(ctx context.Context, st *store.Store, spoolDir string, olderThan time.Time) (int, error) {
	stale, err := st.StaleUploads(ctx, olderThan)
	if err != nil {
		return 0, err
	}
	removed := 0
	for _, up := range stale {
		if err := st.DeleteUpload(ctx, up.ID); err != nil {
			continue
		}
		_ = os.RemoveAll(filepath.Join(spoolDir, "multipart", safeUploadID(up.ID)))
		removed++
	}
	return removed, nil
}

func safeUploadID(id string) string {
	return strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			return r
		}
		return -1
	}, id)
}
