package webui

import (
	"context"
	"testing"

	"s3drive/internal/store"
)

// AGENTS.md: the pool name stays reserved and the namespace cannot move
// while data exists. A store error must block the change, never skip the
// guard.
func TestSettingsGuards(t *testing.T) {
	ctx := context.Background()
	s := newTestServer(t)
	l := language("en")
	acct := &store.Account{Name: "a", Email: "a@example.com", RefreshToken: "r"}
	if err := s.Store.CreateAccount(ctx, acct); err != nil {
		t.Fatal(err)
	}
	if err := s.Store.CreateBucket(ctx, &store.Bucket{Name: "photos", AccountID: acct.ID, FolderID: "f"}); err != nil {
		t.Fatal(err)
	}
	if msg, err := s.poolNameBlocked(ctx, l, "photos", true, "pool"); msg == "" || err != nil {
		t.Errorf("enabling pool on an existing bucket name: msg %q err %v", msg, err)
	}
	if msg, err := s.poolNameBlocked(ctx, l, "free", true, ""); msg != "" || err != nil {
		t.Errorf("free pool name blocked: msg %q err %v", msg, err)
	}
	if msg, err := s.namespaceChangeBlocked(ctx, l); msg == "" || err != nil {
		t.Errorf("namespace move with a bucket: msg %q err %v", msg, err)
	}
	if err := s.Store.Close(); err != nil {
		t.Fatal(err)
	}
	if msg, err := s.poolNameBlocked(ctx, l, "free", true, ""); msg == "" && err == nil {
		t.Error("pool name check passed on an unreadable store")
	}
	if msg, err := s.namespaceChangeBlocked(ctx, l); msg == "" && err == nil {
		t.Error("namespace move allowed on an unreadable store")
	}
	if _, err := s.accountByEmail(ctx, "user@example.com"); err == nil {
		t.Error("account lookup on an unreadable store returned no error, so OAuth would add a duplicate account")
	}
}
