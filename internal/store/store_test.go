package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"s3drive/internal/secure"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	box, err := secure.New(dir, "0000000000000000000000000000000000000000000000000000000000000000")
	must(t, err)
	st, err := Open(filepath.Join(dir, "test.db"), box)
	must(t, err)
	t.Cleanup(func() {
		if err := st.Close(); err != nil {
			t.Errorf("close store: %v", err)
		}
	})
	return st
}

// must stops the test on an unexpected error from a setup step.
func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// wantNotFound fails the test unless err is ErrNotFound.
func wantNotFound(t *testing.T, err error, what string) {
	t.Helper()
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("%s still present: %v", what, err)
	}
}

func testAccessKey() *AccessKey {
	return &AccessKey{
		AccessKey: "S3DTESTKEY", Secret: "secret-value", Label: "backup", Active: true,
		Permission: "ro", Bucket: "photos", Prefix: "2026/",
		ExpiresAt: time.Now().Add(time.Hour).Truncate(time.Second),
	}
}

func TestAccessKeyPolicyScope(t *testing.T) {
	key := testAccessKey()
	if !key.CanRead("photos", "2026/a.jpg") {
		t.Fatal("read policy rejected matching key")
	}
	if key.CanWrite("photos", "2026/a.jpg") {
		t.Fatal("read-only key allowed a write")
	}
	if key.CanRead("other", "2026/a.jpg") || key.CanRead("photos", "2025/a.jpg") {
		t.Fatal("policy leaked outside its scope")
	}
}

func TestAccessKeyRoundTripHidesSecretInList(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	key := testAccessKey()
	must(t, st.CreateAccessKey(ctx, key))

	got, err := st.GetAccessKey(ctx, "S3DTESTKEY")
	must(t, err)
	if got.Secret != "secret-value" || got.Permission != "ro" || got.Bucket != "photos" || got.Prefix != "2026/" {
		t.Fatalf("policy round trip = %+v", got)
	}
	if !got.ExpiresAt.Equal(key.ExpiresAt) {
		t.Fatalf("expiry = %v, want %v", got.ExpiresAt, key.ExpiresAt)
	}

	list, err := st.ListAccessKeys(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("ListAccessKeys = %v, %v", list, err)
	}
	if list[0].Secret != "" {
		t.Fatal("listing exposed the secret")
	}
}

func TestObjectMetaRename(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	must(t, st.SetObjectMeta(ctx, ObjectMeta{
		Bucket: "photos", Key: "old.jpg", ETag: "etag", ContentType: "image/jpeg",
		StorageClass: "STANDARD", Metadata: `{"x":"y"}`, Checksum: "sha",
	}))
	must(t, st.RenameObjectMeta(ctx, "photos", "old.jpg", "new.jpg"))
	_, err := st.GetObjectMeta(ctx, "photos", "old.jpg")
	wantNotFound(t, err, "old metadata")
	m, err := st.GetObjectMeta(ctx, "photos", "new.jpg")
	if err != nil || m.ETag != "etag" || m.ContentType != "image/jpeg" || m.Checksum != "sha" {
		t.Fatalf("renamed metadata = %+v, %v", m, err)
	}
}

func TestPoolIndexRename(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	must(t, st.PutPoolObject(ctx, PoolObject{Key: "old.jpg", AccountID: "acct", FileID: "file", Size: 3}))
	must(t, st.RenamePoolObject(ctx, "old.jpg", "new.jpg"))
	_, err := st.GetPoolObject(ctx, "old.jpg")
	wantNotFound(t, err, "old pool key")
	p, err := st.GetPoolObject(ctx, "new.jpg")
	if err != nil || p.FileID != "file" || p.Size != 3 {
		t.Fatalf("renamed pool object = %+v, %v", p, err)
	}
}

func TestRenameBucketUpdatesReferences(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	must(t, st.CreateAccount(ctx, &Account{ID: "acct", Name: "Test", Email: "test@example.com"}))
	must(t, st.CreateBucket(ctx, &Bucket{Name: "old-bucket", AccountID: "acct", FolderID: "folder"}))
	must(t, st.SetObjectMeta(ctx, ObjectMeta{Bucket: "old-bucket", Key: "a.txt", ETag: "e"}))
	must(t, st.CreateUpload(ctx, &Upload{ID: "u1", Bucket: "old-bucket", Key: "a.txt"}))
	must(t, st.RenameBucket(ctx, "old-bucket", "new-bucket"))
	if _, err := st.GetBucket(ctx, "new-bucket"); err != nil {
		t.Fatalf("renamed bucket missing: %v", err)
	}
	if _, err := st.GetObjectMeta(ctx, "new-bucket", "a.txt"); err != nil {
		t.Fatalf("metadata not moved: %v", err)
	}
	up, err := st.GetUploadByID(ctx, "u1")
	if err != nil || up.Bucket != "new-bucket" {
		t.Fatalf("upload not moved: %+v, %v", up, err)
	}
}

func TestEventFilter(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	old := time.Now().Add(-48 * time.Hour)
	must(t, st.AddEvent(ctx, Event{TS: old, Op: "PutObject", Bucket: "photos", Key: "a.jpg", AccessKey: "K1", Status: 200}))
	must(t, st.AddEvent(ctx, Event{TS: time.Now(), Op: "GetObject", Bucket: "photos", Key: "a.jpg", AccessKey: "K2", Status: 404}))

	events, total, err := st.ListEvents(ctx, EventFilter{Op: "GetObject", Status: "error", Limit: 10})
	if err != nil || total != 1 || len(events) != 1 || events[0].AccessKey != "K2" {
		t.Fatalf("filter = %+v total=%d err=%v", events, total, err)
	}
	events, total, err = st.ListEvents(ctx, EventFilter{Key: "a.jpg", Since: time.Now().Add(-24 * time.Hour), Limit: 10})
	if err != nil || total != 1 || len(events) != 1 {
		t.Fatalf("date filter = %+v total=%d err=%v", events, total, err)
	}
}

func TestUserLifecycle(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	u := &User{Username: "alice", PasswordHash: "hash", Role: "viewer"}
	must(t, st.CreateUser(ctx, u))
	got, err := st.GetUserByUsername(ctx, "alice")
	if err != nil || got.Role != "viewer" {
		t.Fatalf("user round trip = %+v, %v", got, err)
	}
	must(t, st.UpdateUserPassword(ctx, u.ID, "newhash"))
	got, err = st.GetUserByID(ctx, u.ID)
	must(t, err)
	if got.PasswordHash != "newhash" {
		t.Fatal("password hash not updated")
	}
	must(t, st.DeleteUser(ctx, u.ID))
	_, err = st.GetUserByID(ctx, u.ID)
	wantNotFound(t, err, "deleted user")
}
