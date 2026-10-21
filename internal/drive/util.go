package drive

import (
	"crypto/md5"
	"encoding/hex"
	"hash"
	"os"
)

func newSpoolFile(dir string) (*os.File, error) {
	return os.CreateTemp(dir, "s3drive-*")
}

func newMD5() hash.Hash { return md5.New() }

func hexString(b []byte) string { return hex.EncodeToString(b) }

func removeFile(path string) error { return os.Remove(path) }
