package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"s3drive/internal/secure"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	box, err := secure.New(dir, "0000000000000000000000000000000000000000000000000000000000000000")
	if err != nil {
		t.Fatal(err)
	}
	st, err := Open(filepath.Join(dir, "test.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestAccessKeyPoliciesAndSecret(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	expires := time.Now().Add(time.Hour).Truncate(time.Second)
	key := &AccessKey{
		AccessKey: "S3DTESTKEY", Secret: "secret-value", Label: "backup", Active: true,
		Permission: "ro", Bucket: "photos", Prefix: "2026/", ExpiresAt: expires,
	}
	if err := st.CreateAccessKey(ctx, key); err != nil {
		t.Fatal(err)
	}
	if !key.CanRead("photos", "2026/a.jpg") {
		t.Fatal("read policy rejected matching key")
	}
	if key.CanWrite("photos", "2026/a.jpg") {
		t.Fatal("read-only key allowed a write")
	}
	if key.CanRead("other", "2026/a.jpg") || key.CanRead("photos", "2025/a.jpg") {
		t.Fatal("policy leaked outside its scope")
	}

	got, err := st.GetAccessKey(ctx, "S3DTESTKEY")
	if err != nil {
		t.Fatal(err)
	}
	if got.Secret != "secret-value" || got.Permission != "ro" || got.Bucket != "photos" || got.Prefix != "2026/" {
		t.Fatalf("policy round trip = %+v", got)
	}
	if !got.ExpiresAt.Equal(expires) {
		t.Fatalf("expiry = %v, want %v", got.ExpiresAt, expires)
	}

	list, err := st.ListAccessKeys(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("ListAccessKeys = %v, %v", list, err)
	}
	if list[0].Secret != "" {
		t.Fatal("listing exposed the secret")
	}
}

func TestObjectMetaRenameAndPoolIndex(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	if err := st.SetObjectMeta(ctx, ObjectMeta{
		Bucket: "photos", Key: "old.jpg", ETag: "etag", ContentType: "image/jpeg",
		StorageClass: "STANDARD", Metadata: `{"x":"y"}`, Checksum: "sha",
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.RenameObjectMeta(ctx, "photos", "old.jpg", "new.jpg"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetObjectMeta(ctx, "photos", "old.jpg"); err != ErrNotFound {
		t.Fatalf("old metadata still present: %v", err)
	}
	m, err := st.GetObjectMeta(ctx, "photos", "new.jpg")
	if err != nil || m.ETag != "etag" || m.ContentType != "image/jpeg" || m.Checksum != "sha" {
		t.Fatalf("renamed metadata = %+v, %v", m, err)
	}

	if err := st.PutPoolObject(ctx, PoolObject{Key: "old.jpg", AccountID: "acct", FileID: "file", Size: 3}); err != nil {
		t.Fatal(err)
	}
	if err := st.RenamePoolObject(ctx, "old.jpg", "new.jpg"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetPoolObject(ctx, "old.jpg"); err != ErrNotFound {
		t.Fatalf("old pool key still present: %v", err)
	}
	p, err := st.GetPoolObject(ctx, "new.jpg")
	if err != nil || p.FileID != "file" || p.Size != 3 {
		t.Fatalf("renamed pool object = %+v, %v", p, err)
	}
}

func TestRenameBucketUpdatesReferences(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	acct := &Account{ID: "acct", Name: "Test", Email: "test@example.com"}
	if err := st.CreateAccount(ctx, acct); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateBucket(ctx, &Bucket{Name: "old-bucket", AccountID: "acct", FolderID: "folder"}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetObjectMeta(ctx, ObjectMeta{Bucket: "old-bucket", Key: "a.txt", ETag: "e"}); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateUpload(ctx, &Upload{ID: "u1", Bucket: "old-bucket", Key: "a.txt"}); err != nil {
		t.Fatal(err)
	}
	if err := st.RenameBucket(ctx, "old-bucket", "new-bucket"); err != nil {
		t.Fatal(err)
	}
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

func TestEventFilterAndUserLifecycle(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	old := time.Now().Add(-48 * time.Hour)
	for _, e := range []Event{
		{TS: old, Op: "PutObject", Bucket: "photos", Key: "a.jpg", AccessKey: "K1", Status: 200},
		{TS: time.Now(), Op: "GetObject", Bucket: "photos", Key: "a.jpg", AccessKey: "K2", Status: 404},
	} {
		if err := st.AddEvent(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	events, total, err := st.ListEvents(ctx, EventFilter{Op: "GetObject", Status: "error", Limit: 10})
	if err != nil || total != 1 || len(events) != 1 || events[0].AccessKey != "K2" {
		t.Fatalf("filter = %+v total=%d err=%v", events, total, err)
	}
	events, total, err = st.ListEvents(ctx, EventFilter{Key: "a.jpg", Since: time.Now().Add(-24 * time.Hour), Limit: 10})
	if err != nil || total != 1 || len(events) != 1 {
		t.Fatalf("date filter = %+v total=%d err=%v", events, total, err)
	}

	u := &User{Username: "alice", PasswordHash: "hash", Role: "viewer"}
	if err := st.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetUserByUsername(ctx, "alice")
	if err != nil || got.Role != "viewer" {
		t.Fatalf("user round trip = %+v, %v", got, err)
	}
	if err := st.UpdateUserPassword(ctx, u.ID, "newhash"); err != nil {
		t.Fatal(err)
	}
	got, _ = st.GetUserByID(ctx, u.ID)
	if got.PasswordHash != "newhash" {
		t.Fatal("password hash not updated")
	}
	if err := st.DeleteUser(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetUserByID(ctx, u.ID); err != ErrNotFound {
		t.Fatalf("deleted user still present: %v", err)
	}
}
