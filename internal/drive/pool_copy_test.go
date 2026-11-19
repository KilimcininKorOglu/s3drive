package drive

import (
	"context"
	"testing"

	"s3drive/internal/store"
)

// Before a pool write replaces a key, the old index entry must be known so
// the old Drive copy can be removed. A missing entry is fine; an unreadable
// index must stop the write instead of being treated as "no old copy".
func TestPreviousPoolCopy(t *testing.T) {
	ctx := context.Background()
	st := openStore(t)
	svc := &Service{Store: st}
	pool, pinned := &BucketRef{Pool: true}, &BucketRef{}
	if err := st.PutPoolObject(ctx, store.PoolObject{Key: "k", AccountID: "a", FileID: "f1", Size: 3}); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		ref     *BucketRef
		key     string
		wantID  string // "" means no previous copy
		closeDB bool
		wantErr bool
	}{
		{"missing entry", pool, "missing", "", false, false},
		{"existing entry", pool, "k", "f1", false, false},
		{"pinned bucket", pinned, "k", "", false, false},
		{"unreadable index", pool, "k", "", true, true},
	}
	for _, c := range cases {
		if c.closeDB {
			if err := st.Close(); err != nil {
				t.Fatal(err)
			}
		}
		p, err := svc.previousPoolCopy(ctx, c.ref, c.key)
		gotID := ""
		if p != nil {
			gotID = p.FileID
		}
		if (err != nil) != c.wantErr || gotID != c.wantID {
			t.Errorf("%s: file %q err %v, want %q wantErr=%v", c.name, gotID, err, c.wantID, c.wantErr)
		}
	}
}
