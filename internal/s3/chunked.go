package s3

import (
	"bufio"
	"bytes"
	"crypto/sha1" // #nosec G505 -- S3 x-amz-checksum-sha1 trailer, not a security primitive
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"hash/crc32"
	"io"
	"strconv"
	"strings"
)

// newPayloadReader wraps an AWS streaming (aws-chunked) body. For the signed
// variants, every chunk signature is verified against the request signature.
// Trailer checksums are verified when the client advertises them.
func newPayloadReader(body io.ReadCloser, auth *Auth, trailerHeader string) io.ReadCloser {
	if auth == nil || !strings.HasPrefix(auth.PayloadHash, "STREAMING-") {
		return body
	}
	verify := strings.HasPrefix(auth.PayloadHash, "STREAMING-AWS4-HMAC-SHA256-PAYLOAD")
	c := &chunkedReader{
		br:        bufio.NewReaderSize(body, 64*1024),
		body:      body,
		auth:      auth,
		verify:    verify,
		prevSig:   auth.Signature,
		chunkHash: sha256.New(),
		trailers:  map[string]hash.Hash{},
	}
	for name := range strings.SplitSeq(trailerHeader, ",") {
		name = strings.ToLower(strings.TrimSpace(name))
		switch name {
		case "x-amz-checksum-sha256":
			c.trailers[name] = sha256.New()
		case "x-amz-checksum-sha1":
			c.trailers[name] = sha1.New() // #nosec G401 -- S3 x-amz-checksum-sha1 trailer
		case "x-amz-checksum-crc32":
			c.trailers[name] = crc32.NewIEEE()
		case "x-amz-checksum-crc32c":
			c.trailers[name] = crc32.New(crc32.MakeTable(crc32.Castagnoli))
		}
	}
	return c
}

type chunkedReader struct {
	br        *bufio.Reader
	body      io.ReadCloser
	auth      *Auth
	verify    bool
	remaining int64
	done      bool
	prevSig   string
	chunkHash hash.Hash
	chunkSig  string
	trailers  map[string]hash.Hash
}

func (c *chunkedReader) Read(p []byte) (int, error) {
	for {
		if err := c.ensureChunk(); err != nil {
			return 0, err
		}
		n := len(p)
		if int64(n) > c.remaining {
			n = int(c.remaining)
		}
		read, err := c.br.Read(p[:n])
		if read > 0 {
			if ferr := c.consume(p[:read]); ferr != nil && err == nil {
				err = ferr
			}
			return read, err
		}
		if err != nil {
			return 0, err
		}
	}
}

// ensureChunk positions the reader inside a data chunk; it returns io.EOF
// once the final chunk and trailers have been read.
func (c *chunkedReader) ensureChunk() error {
	if c.done {
		return io.EOF
	}
	if c.remaining != 0 {
		return nil
	}
	if err := c.nextChunk(); err != nil {
		return err
	}
	if c.done {
		return io.EOF
	}
	return nil
}

// consume feeds payload bytes to the chunk signature and trailer checksums
// and verifies the chunk once it is complete.
func (c *chunkedReader) consume(b []byte) error {
	c.remaining -= int64(len(b))
	if c.verify {
		c.chunkHash.Write(b)
	}
	for _, h := range c.trailers {
		_, _ = h.Write(b) // hash.Hash.Write never returns an error
	}
	if c.remaining == 0 {
		return c.finishChunk()
	}
	return nil
}

func (c *chunkedReader) nextChunk() error {
	line, err := c.readLine()
	if err != nil {
		return err
	}
	sizePart, sigPart, _ := strings.Cut(line, ";")
	size, err := strconv.ParseInt(strings.TrimSpace(sizePart), 16, 64)
	if err != nil || size < 0 {
		return fmt.Errorf("invalid aws-chunked chunk header %q", line)
	}
	if c.verify {
		_, sig, _ := strings.Cut(sigPart, "=")
		if sig == "" {
			return errors.New("aws-chunked: missing chunk signature")
		}
		c.chunkSig = strings.TrimSpace(sig)
		c.chunkHash.Reset()
	}
	if size == 0 {
		return c.finishStream()
	}
	c.remaining = size
	return nil
}

// finishStream handles the zero-size final chunk: it is signed as well, so
// its signature is verified before the trailer block is read and checked.
func (c *chunkedReader) finishStream() error {
	if err := c.checkChunkSignature(); err != nil {
		return err
	}
	seen, err := c.readTrailers()
	if err != nil {
		return err
	}
	if err := c.verifyTrailers(seen); err != nil {
		return err
	}
	c.done = true
	return nil
}

// readTrailers consumes optional "name: value" trailers up to the blank
// line (or EOF) that ends the body.
func (c *chunkedReader) readTrailers() (map[string]string, error) {
	seen := map[string]string{}
	for {
		line, err := c.readLine()
		if errors.Is(err, io.EOF) || (err == nil && line == "") {
			return seen, nil
		}
		if err != nil {
			return nil, err
		}
		if name, value, ok := strings.Cut(line, ":"); ok {
			seen[strings.ToLower(strings.TrimSpace(name))] = strings.TrimSpace(value)
		}
	}
}

func (c *chunkedReader) verifyTrailers(seen map[string]string) error {
	for name, h := range c.trailers {
		want := seen[name]
		if want == "" {
			return fmt.Errorf("aws-chunked: missing trailer %s", name)
		}
		if base64.StdEncoding.EncodeToString(h.Sum(nil)) != want {
			return fmt.Errorf("aws-chunked: %s checksum mismatch", name)
		}
	}
	return nil
}

func (c *chunkedReader) finishChunk() error {
	if err := c.discardCRLF(); err != nil {
		return err
	}
	return c.checkChunkSignature()
}

func (c *chunkedReader) checkChunkSignature() error {
	if !c.verify {
		return nil
	}
	empty := sha256Hex("")
	stringToSign := "AWS4-HMAC-SHA256-PAYLOAD\n" + c.auth.DateTime + "\n" + c.auth.Scope + "\n" +
		c.prevSig + "\n" + empty + "\n" + hex.EncodeToString(c.chunkHash.Sum(nil))
	expected := hex.EncodeToString(hmacSHA256(c.auth.SigningKey, stringToSign))
	if !strings.EqualFold(expected, c.chunkSig) {
		return errors.New("aws-chunked: chunk signature mismatch")
	}
	c.prevSig = strings.ToLower(c.chunkSig)
	return nil
}

func (c *chunkedReader) readLine() (string, error) {
	line, err := c.br.ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	line = strings.TrimSuffix(line, "\n")
	line = strings.TrimSuffix(line, "\r")
	return line, nil
}

func (c *chunkedReader) discardCRLF() error {
	buf := make([]byte, 2)
	if _, err := io.ReadFull(c.br, buf); err != nil {
		return err
	}
	if !bytes.Equal(buf, []byte("\r\n")) {
		return errors.New("aws-chunked: missing chunk terminator")
	}
	return nil
}

func (c *chunkedReader) Close() error { return c.body.Close() }
