//go:build unix

package drive

import (
	"math"
	"testing"
)

// Free space must never be reported as negative, whatever the file system
// returns, because a negative value would fail every quota check.
func TestBlockBytesNeverNegative(t *testing.T) {
	cases := []struct {
		blocks, size uint64
		want         int64
	}{
		{0, 4096, 0},
		{1000, 4096, 4096000},
		{math.MaxUint64, 4096, math.MaxInt64},
		{1 << 62, 4, math.MaxInt64},
		{1 << 62, 2, math.MaxInt64},
		{1 << 61, 4, math.MaxInt64},
	}
	for _, c := range cases {
		if got := blockBytes(c.blocks, c.size); got != c.want {
			t.Errorf("blockBytes(%d, %d) = %d, want %d", c.blocks, c.size, got, c.want)
		}
	}
}
