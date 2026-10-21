// Package secure encrypts secrets at rest with AES-256-GCM.
package secure

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Box seals and opens short secrets (refresh tokens, client secrets, S3 keys).
type Box struct {
	aead cipher.AEAD
}

// New loads the master key from envKey if set, otherwise from
// <dataDir>/master.key (created with 0600 on first run).
func New(dataDir, envKey string) (*Box, error) {
	key, err := masterKey(dataDir, envKey)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Box{aead: aead}, nil
}

func masterKey(dataDir, envKey string) ([]byte, error) {
	if envKey != "" {
		key, err := decodeKey(envKey)
		if err != nil {
			return nil, fmt.Errorf("S3DRIVE_MASTER_KEY: %w", err)
		}
		return key, nil
	}

	path := filepath.Join(dataDir, "master.key")
	raw, err := os.ReadFile(path)
	if err == nil {
		key, decErr := decodeKey(strings.TrimSpace(string(raw)))
		if decErr != nil {
			return nil, fmt.Errorf("read %s: %w", path, decErr)
		}
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	encoded := base64.RawURLEncoding.EncodeToString(key)
	if err := os.WriteFile(path, []byte(encoded+"\n"), 0o600); err != nil {
		return nil, fmt.Errorf("write master key: %w", err)
	}
	return key, nil
}

func decodeKey(s string) ([]byte, error) {
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil && len(b) == 32 {
		return b, nil
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) == 32 {
		return b, nil
	}
	if b, err := hex.DecodeString(s); err == nil && len(b) == 32 {
		return b, nil
	}
	return nil, errors.New("key must be 32 bytes encoded as base64 or hex")
}

// Seal encrypts plaintext and returns base64url(nonce||ciphertext).
func (b *Box) Seal(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	out := b.aead.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.RawURLEncoding.EncodeToString(out), nil
}

// Open decrypts a value produced by Seal.
func (b *Box) Open(encoded string) (string, error) {
	if encoded == "" {
		return "", nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("decode secret: %w", err)
	}
	if len(raw) < b.aead.NonceSize() {
		return "", errors.New("secret is truncated")
	}
	nonce, ciphertext := raw[:b.aead.NonceSize()], raw[b.aead.NonceSize():]
	out, err := b.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", errors.New("cannot decrypt secret (wrong master key?)")
	}
	return string(out), nil
}
