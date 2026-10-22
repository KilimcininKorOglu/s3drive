package drive

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"hash"
	"os"
	"strings"
)

// Drive cannot represent empty, "." or ".." path components. S3 can, so those
// components are escaped into a private namespace and decoded on the way out.
const segEscape = "~s3drive~"

func encodeSegment(seg string) string {
	if seg == "" || seg == "." || seg == ".." || strings.HasPrefix(seg, segEscape) {
		return segEscape + base64.RawURLEncoding.EncodeToString([]byte(seg))
	}
	return seg
}

func decodeSegment(name string) string {
	if !strings.HasPrefix(name, segEscape) {
		return name
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(name, segEscape))
	if err != nil {
		return name
	}
	return string(raw)
}

func newSpoolFile(dir string) (*os.File, error) {
	return os.CreateTemp(dir, "s3drive-*")
}

func newMD5() hash.Hash { return md5.New() }

func hexString(b []byte) string { return hex.EncodeToString(b) }

func removeFile(path string) error { return os.Remove(path) }
