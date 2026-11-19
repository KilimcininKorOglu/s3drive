package store

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
)

// An OAuth state is single-use (RFC 6749 section 10.12): however many
// callbacks race for it, exactly one may consume it.
func TestConsumeOAuthStateIsSingleUseUnderConcurrency(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	const rounds, racers = 50, 8
	for round := range rounds {
		state := fmt.Sprintf("state-%d", round)
		if err := st.CreateOAuthState(ctx, state, "verifier", "acct"); err != nil {
			t.Fatal(err)
		}
		var ok atomic.Int32
		var wg sync.WaitGroup
		start := make(chan struct{})
		for range racers {
			wg.Go(func() {
				<-start
				v, _, err := st.ConsumeOAuthState(ctx, state)
				switch {
				case err == nil && v == "verifier":
					ok.Add(1)
				case errors.Is(err, ErrNotFound):
				default:
					t.Errorf("ConsumeOAuthState: v=%q err=%v", v, err)
				}
			})
		}
		close(start)
		wg.Wait()
		if n := ok.Load(); n != 1 {
			t.Fatalf("round %d: state consumed %d times, want exactly 1", round, n)
		}
	}
}

func TestConsumeOAuthStateRejectsReplay(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	if err := st.CreateOAuthState(ctx, "s", "v", "a"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.ConsumeOAuthState(ctx, "s"); err != nil {
		t.Fatalf("first consume: %v", err)
	}
	if _, _, err := st.ConsumeOAuthState(ctx, "s"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("replayed consume err = %v, want ErrNotFound", err)
	}
}
