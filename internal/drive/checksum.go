package drive

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"hash/crc32"
	"io"
	"strings"
)

// Checksums are computed while spooling an upload.
type Checksums struct {
	MD5    string
	SHA256 string
	SHA1   string
	CRC32  string
	CRC32C string
}

func (s *Service) spoolHashes(r io.Reader) (path string, size int64, sums Checksums, err error) {
	if err := s.checkSpoolCapacity(); err != nil {
		return "", 0, Checksums{}, err
	}
	f, err := newSpoolFile(s.SpoolDir)
	if err != nil {
		return "", 0, Checksums{}, err
	}
	path = f.Name()
	hMD5 := md5.New()
	hSHA256 := sha256.New()
	hSHA1 := sha1.New()
	hCRC32 := crc32.NewIEEE()
	hCRC32C := crc32.New(crc32.MakeTable(crc32.Castagnoli))
	writers := []io.Writer{f, hMD5, hSHA256, hSHA1, hCRC32, hCRC32C}
	var src io.Reader = r
	if s.MaxObjectBytes > 0 {
		src = io.LimitReader(r, s.MaxObjectBytes+1)
	}
	n, err := io.Copy(io.MultiWriter(writers...), src)
	cerr := f.Close()
	if err != nil {
		_ = removeFile(path)
		return "", 0, Checksums{}, err
	}
	if cerr != nil {
		_ = removeFile(path)
		return "", 0, Checksums{}, cerr
	}
	if s.MaxObjectBytes > 0 && n > s.MaxObjectBytes {
		_ = removeFile(path)
		return "", 0, Checksums{}, newError("EntityTooLarge", "object exceeds the configured %s limit", FormatBytes(s.MaxObjectBytes))
	}
	sums = Checksums{
		MD5:    hex.EncodeToString(hMD5.Sum(nil)),
		SHA256: base64.StdEncoding.EncodeToString(hSHA256.Sum(nil)),
		SHA1:   base64.StdEncoding.EncodeToString(hSHA1.Sum(nil)),
		CRC32:  base64.StdEncoding.EncodeToString(hCRC32.Sum(nil)),
		CRC32C: base64.StdEncoding.EncodeToString(hCRC32C.Sum(nil)),
	}
	return path, n, sums, nil
}

// PutChecked spools a stream, validates x-amz-checksum-* values and uploads it.
func (s *Service) PutChecked(ctx context.Context, bucketName, key, contentType string, r io.Reader, expected map[string]string) (*PutResult, error) {
	path, size, sums, err := s.spoolHashes(r)
	if err != nil {
		return nil, err
	}
	defer removeFile(path)
	for algorithm, want := range expected {
		if want == "" {
			continue
		}
		var got string
		switch strings.ToLower(algorithm) {
		case "md5":
			got = sums.MD5
		case "sha256":
			got = sums.SHA256
		case "sha1":
			got = sums.SHA1
		case "crc32":
			got = sums.CRC32
		case "crc32c":
			got = sums.CRC32C
		default:
			return nil, newError("InvalidRequest", "unsupported checksum algorithm %q", algorithm)
		}
		if !strings.EqualFold(got, want) {
			return nil, newError("BadDigest", "the %s checksum you specified did not match what we received", algorithm)
		}
	}
	return s.putFile(ctx, bucketName, key, contentType, path, size, sums.MD5)
}

// ChecksumHeader encodes the validated checksums for storage/response.
func ChecksumHeader(expected map[string]string) string {
	var parts []string
	for _, algorithm := range []string{"sha256", "sha1", "crc32", "crc32c"} {
		if v := expected[algorithm]; v != "" {
			parts = append(parts, "x-amz-checksum-"+algorithm+"="+v)
		}
	}
	return strings.Join(parts, ";")
}
