//go:build unix

package drive

import (
	"math"
	"math/bits"
	"syscall"
)

func availableDisk(path string) (int64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, err
	}
	return blockBytes(uint64(st.Bavail), uint64(st.Bsize)), nil // #nosec G115 -- block size is never negative
}

// blockBytes multiplies a block count by a block size and saturates at
// math.MaxInt64 instead of wrapping into a negative byte count.
func blockBytes(blocks, size uint64) int64 {
	hi, lo := bits.Mul64(blocks, size)
	if hi != 0 || lo > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(lo)
}
