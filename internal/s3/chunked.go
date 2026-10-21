package s3

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"strconv"
	"strings"
)

// newPayloadReader wraps an AWS streaming (aws-chunked) body. For the signed
// variants, every chunk signature is verified against the request signature.
func newPayloadReader(body io.ReadCloser, auth *Auth) io.ReadCloser {
	if auth == nil || !strings.HasPrefix(auth.PayloadHash, "STREAMING-") {
		return body
	}
	verify := strings.HasPrefix(auth.PayloadHash, "STREAMING-AWS4-HMAC-SHA256-PAYLOAD")
	return &chunkedReader{
		br:        bufio.NewReaderSize(body, 64*1024),
		body:      body,
		auth:      auth,
		verify:    verify,
		prevSig:   auth.Signature,
		chunkHash: sha256.New(),
	}
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
		// Consume optional trailers, then the terminating blank line.
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
