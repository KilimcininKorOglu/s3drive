package s3

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestUnsignedChunkedTrailerChecksum(t *testing.T) {
	payload := "hello drive"
	sum := sha256.Sum256([]byte(payload))
	body := fmt.Sprintf("6\r\nhello \r\n5\r\ndrive\r\n0\r\nx-amz-checksum-sha256: %s\r\n\r\n",
		base64.StdEncoding.EncodeToString(sum[:]))
	r := newPayloadReader(io.NopCloser(strings.NewReader(body)), &Auth{
		PayloadHash: "STREAMING-UNSIGNED-PAYLOAD-TRAILER",
	}, "x-amz-checksum-sha256")
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != payload {
		t.Fatalf("payload = %q", got)
	}

	bad := fmt.Sprintf("6\r\nhello \r\n5\r\ndrive\r\n0\r\nx-amz-checksum-sha256: %s\r\n\r\n",
		base64.StdEncoding.EncodeToString(make([]byte, 32)))
	r = newPayloadReader(io.NopCloser(strings.NewReader(bad)), &Auth{
		PayloadHash: "STREAMING-UNSIGNED-PAYLOAD-TRAILER",
	}, "x-amz-checksum-sha256")
	if _, err := io.ReadAll(r); err == nil {
		t.Fatal("bad trailer checksum accepted")
	}
}

func TestSignedChunkedVerifiesFinalChunk(t *testing.T) {
	auth := &Auth{
		PayloadHash: "STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
		SigningKey:  []byte("test-signing-key"),
		DateTime:    "20260101T000000Z",
		Scope:       "20260101/us-east-1/s3/aws4_request",
		Signature:   "seed",
	}
	sign := func(prev, data string) string {
		empty := sha256Hex("")
		sum := sha256.Sum256([]byte(data))
		sts := "AWS4-HMAC-SHA256-PAYLOAD\n" + auth.DateTime + "\n" + auth.Scope + "\n" +
			prev + "\n" + empty + "\n" + hex.EncodeToString(sum[:])
		return hex.EncodeToString(hmacSHA256(auth.SigningKey, sts))
	}
	sig1 := sign(auth.Signature, "hello")
	sig2 := sign(sig1, "")
	body := fmt.Sprintf("5;chunk-signature=%s\r\nhello\r\n0;chunk-signature=%s\r\n\r\n", sig1, sig2)
	r := newPayloadReader(io.NopCloser(strings.NewReader(body)), auth, "")
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("payload = %q", got)
	}

	bad := fmt.Sprintf("5;chunk-signature=%s\r\nhello\r\n0;chunk-signature=%s\r\n\r\n", sig1, strings.Repeat("0", 64))
	r = newPayloadReader(io.NopCloser(strings.NewReader(bad)), auth, "")
	if _, err := io.ReadAll(r); err == nil {
		t.Fatal("bad final chunk signature accepted")
	}
}

func TestValidPayloadHash(t *testing.T) {
	good := []string{
		"", "UNSIGNED-PAYLOAD",
		"STREAMING-UNSIGNED-PAYLOAD",
		"STREAMING-UNSIGNED-PAYLOAD-TRAILER",
		"STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
		"STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER",
		strings.Repeat("a", 64),
	}
	for _, v := range good {
		if !validPayloadHash(v) {
			t.Errorf("validPayloadHash(%q) = false", v)
		}
	}
	bad := []string{"STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD", "nope", strings.Repeat("z", 64)}
	for _, v := range bad {
		if validPayloadHash(v) {
			t.Errorf("validPayloadHash(%q) = true", v)
		}
	}
}

func TestPayloadHashMismatch(t *testing.T) {
	sum := sha256.Sum256([]byte("expected"))
	r := verifyPayloadHash(io.NopCloser(strings.NewReader("actual")), hex.EncodeToString(sum[:]))
	if _, err := io.ReadAll(r); err == nil {
		t.Fatal("payload hash mismatch accepted")
	}
}

func TestSplitPathEscapingAndEmptySegments(t *testing.T) {
	cases := []struct {
		path, bucket, key string
	}{
		{"/", "", ""},
		{"/photos", "photos", ""},
		{"/photos/", "photos", ""},
		{"/photos/a//b%20c.txt", "photos", "a//b c.txt"},
		{"/photos//leading.txt", "photos", "/leading.txt"},
		{"/photos/caf%C3%A9+men%C3%BC.txt", "photos", "café+menü.txt"},
	}
	for _, tc := range cases {
		req := httptest.NewRequest("GET", tc.path, nil)
		bucket, key := splitPath(req)
		if bucket != tc.bucket || key != tc.key {
			t.Errorf("splitPath(%q) = %q, %q; want %q, %q", tc.path, bucket, key, tc.bucket, tc.key)
		}
	}
}
