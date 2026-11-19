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

	if p, err := svc.previousPoolCopy(ctx, pool, "missing"); p != nil || err != nil {
		t.Fatalf("missing entry: %v, %v; want nil, nil", p, err)
	}
	if err := st.PutPoolObject(ctx, store.PoolObject{Key: "k", AccountID: "a", FileID: "f1", Size: 3}); err != nil {
		t.Fatal(err)
	}
	if p, err := svc.previousPoolCopy(ctx, pool, "k"); err != nil || p == nil || p.FileID != "f1" {
		t.Fatalf("existing entry: %+v, %v", p, err)
	}
	if p, err := svc.previousPoolCopy(ctx, pinned, "k"); p != nil || err != nil {
		t.Fatalf("pinned bucket: %v, %v; want nil, nil", p, err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.previousPoolCopy(ctx, pool, "k"); err == nil {
		t.Fatal("unreadable pool index accepted")
	}
}
