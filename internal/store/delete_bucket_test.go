package store

import (
	"context"
	"testing"
)

// DeleteBucket must be all or nothing: if removing any related row fails, the
// bucket mapping stays and the caller sees the error, so a later bucket with
// the same name never inherits stale metadata or resumable sessions.
func TestDeleteBucketIsAtomic(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	if err := st.CreateAccount(ctx, &Account{ID: "acct", Name: "Test", Email: "test@example.com"}); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateBucket(ctx, &Bucket{Name: "b", AccountID: "acct", FolderID: "folder"}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutDriveSession(ctx, DriveSession{Bucket: "b", Key: "k", AccountID: "acct", SessionURL: "https://upload.example/s", Size: 10}); err != nil {
		t.Fatal(err)
	}
	// Simulate a failure on the last cleanup statement.
	if _, err := st.db.ExecContext(ctx, `CREATE TRIGGER fail_session_delete BEFORE DELETE ON drive_sessions
		BEGIN SELECT RAISE(ABORT, 'injected failure'); END`); err != nil {
		t.Fatal(err)
	}

	if err := st.DeleteBucket(ctx, "b"); err == nil {
		t.Fatal("DeleteBucket returned nil although cleanup failed")
	}
	if _, err := st.GetBucket(ctx, "b"); err != nil {
		t.Fatalf("bucket mapping removed despite the failed cleanup: %v", err)
	}
	if _, err := st.GetDriveSession(ctx, "b", "k"); err != nil {
		t.Fatalf("drive session lost: %v", err)
	}

	if _, err := st.db.ExecContext(ctx, `DROP TRIGGER fail_session_delete`); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteBucket(ctx, "b"); err != nil {
		t.Fatalf("DeleteBucket: %v", err)
	}
	if _, err := st.GetBucket(ctx, "b"); err == nil {
		t.Fatal("bucket mapping still present after DeleteBucket")
	}
	if _, err := st.GetDriveSession(ctx, "b", "k"); err == nil {
		t.Fatal("drive session still present after DeleteBucket")
	}
}
