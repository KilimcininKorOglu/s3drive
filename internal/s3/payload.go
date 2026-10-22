package s3

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"strings"
)

var errPayloadHashMismatch = errors.New("the provided x-amz-content-sha256 does not match the request body")

// validPayloadHash restricts x-amz-content-sha256 to the forms this server can
// actually verify. Silently accepting an unknown streaming algorithm would
// let a caller send unverified bytes under a valid request signature.
func validPayloadHash(value string) bool {
	value = strings.TrimSpace(value)
	switch value {
	case "", "UNSIGNED-PAYLOAD",
		"STREAMING-UNSIGNED-PAYLOAD",
		"STREAMING-UNSIGNED-PAYLOAD-TRAILER",
		"STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
		"STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER":
		return true
	}
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

// verifyPayloadHash wraps a normal (non-streaming) signed body and validates
// the concrete SHA-256 published in x-amz-content-sha256. Chunked signing is
// verified by the chunk decoder instead.
func verifyPayloadHash(body io.ReadCloser, payloadHash string) io.ReadCloser {
	payloadHash = strings.ToLower(strings.TrimSpace(payloadHash))
	if len(payloadHash) != 64 {
		return body
	}
	if _, err := hex.DecodeString(payloadHash); err != nil {
		return body
	}
	return &hashReader{body: body, want: payloadHash, h: sha256.New()}
}

type hashReader struct {
	body io.ReadCloser
	want string
	h    hash.Hash
	done bool
}

func (r *hashReader) Read(p []byte) (int, error) {
	n, err := r.body.Read(p)
	if n > 0 {
		_, _ = r.h.Write(p[:n])
	}
	if err == io.EOF && !r.done {
		r.done = true
		got := hex.EncodeToString(r.h.Sum(nil))
		if subtle.ConstantTimeCompare([]byte(got), []byte(r.want)) != 1 {
			return n, errPayloadHashMismatch
		}
	}
	return n, err
}

func (r *hashReader) Close() error { return r.body.Close() }
