package s3

import (
	"bufio"
	"bytes"
	"crypto/sha1"
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
	for _, name := range strings.Split(trailerHeader, ",") {
		name = strings.ToLower(strings.TrimSpace(name))
		switch name {
		case "x-amz-checksum-sha256":
			c.trailers[name] = sha256.New()
		case "x-amz-checksum-sha1":
			c.trailers[name] = sha1.New()
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
		if c.done {
			return 0, io.EOF
		}
		if c.remaining == 0 {
			if err := c.nextChunk(); err != nil {
				return 0, err
			}
			if c.done {
				return 0, io.EOF
			}
		}
		n := len(p)
		if int64(n) > c.remaining {
			n = int(c.remaining)
		}
		read, err := c.br.Read(p[:n])
		if read > 0 {
			c.remaining -= int64(read)
			if c.verify {
				c.chunkHash.Write(p[:read])
			}
			for _, h := range c.trailers {
				_, _ = h.Write(p[:read])
			}
			if c.remaining == 0 {
				if ferr := c.finishChunk(); ferr != nil && err == nil {
					err = ferr
				}
			}
		}
		if read > 0 {
			return read, err
		}
		if err != nil {
			return 0, err
		}
	}
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
		// The zero-size chunk is signed as well; verify it before consuming
		// the trailer block.
		if err := c.checkChunkSignature(); err != nil {
			return err
		}
		// Consume optional trailers, then the terminating blank line.
		seen := map[string]string{}
		for {
			line, err := c.readLine()
			if err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				return err
			}
			if line == "" {
				break
			}
			name, value, ok := strings.Cut(line, ":")
			if ok {
				seen[strings.ToLower(strings.TrimSpace(name))] = strings.TrimSpace(value)
			}
		}
		for name, h := range c.trailers {
			want, ok := seen[name]
			if !ok || want == "" {
				return fmt.Errorf("aws-chunked: missing trailer %s", name)
			}
			got := base64.StdEncoding.EncodeToString(h.Sum(nil))
			if got != want {
				return fmt.Errorf("aws-chunked: %s checksum mismatch", name)
			}
		}
		c.done = true
		return nil
	}
	c.remaining = size
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
