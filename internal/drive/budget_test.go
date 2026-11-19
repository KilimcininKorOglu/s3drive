package drive

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"s3drive/internal/store"
)

// The daily upload limit holds: usage plus the new bytes must fit, and a
// usage counter that cannot be read must not lift the limit.
func TestWithinDailyBudget(t *testing.T) {
	ctx := context.Background()
	st := openStore(t)
	acct := &store.Account{Name: "a", Email: "a@example.com", RefreshToken: "r"}
	if err := st.CreateAccount(ctx, acct); err != nil {
		t.Fatal(err)
	}
	svc := &Service{Store: st, DailyUploadBytes: 100, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if err := st.AddUploadUsage(ctx, acct.ID, 60); err != nil {
		t.Fatal(err)
	}
	if !svc.withinDailyBudget(ctx, acct, 40) {
		t.Error("60+40 of 100 rejected")
	}
	if svc.withinDailyBudget(ctx, acct, 41) {
		t.Error("60+41 of 100 accepted")
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	if svc.withinDailyBudget(ctx, acct, 1) {
		t.Error("unreadable usage counter accepted an upload")
	}
	svc.DailyUploadBytes = 0
	if !svc.withinDailyBudget(ctx, acct, 1<<40) {
		t.Error("no daily limit configured, upload rejected")
	}
}
