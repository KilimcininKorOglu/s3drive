package webui

import (
	"context"
	"testing"

	"s3drive/internal/store"
)

type guardCase struct {
	name    string
	check   func() (string, error)
	blocked bool // want a message or an error
}

func runGuardCases(t *testing.T, cases []guardCase) {
	t.Helper()
	for _, c := range cases {
		msg, err := c.check()
		if got := msg != "" || err != nil; got != c.blocked {
			t.Errorf("%s: msg %q err %v, want blocked=%v", c.name, msg, err, c.blocked)
		}
	}
}

// AGENTS.md: the pool name stays reserved and the namespace cannot move
// while data exists. A store error must block the change, never skip the
// guard, and the OAuth account lookup must report it instead of adding a
// duplicate account.
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
	poolName := func(name string) func() (string, error) {
		return func() (string, error) { return s.poolNameBlocked(ctx, l, name, true, "") }
	}
	namespace := func() (string, error) { return s.namespaceChangeBlocked(ctx, l) }
	lookup := func() (string, error) { _, err := s.accountByEmail(ctx, "user@example.com"); return "", err }

	runGuardCases(t, []guardCase{
		{"pool on an existing bucket name", poolName("photos"), true},
		{"free pool name", poolName("free"), false},
		{"namespace move with a bucket", namespace, true},
		{"account lookup", lookup, false},
	})
	if err := s.Store.Close(); err != nil {
		t.Fatal(err)
	}
	runGuardCases(t, []guardCase{
		{"pool name on an unreadable store", poolName("free"), true},
		{"namespace move on an unreadable store", namespace, true},
		{"account lookup on an unreadable store", lookup, true},
	})
}
