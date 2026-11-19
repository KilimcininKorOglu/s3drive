// Package pctenc percent-encodes strings the way S3, SigV4 and the Drive API
// expect: every byte outside the RFC 3986 unreserved set becomes %XX with
// upper-case hex digits.
package pctenc

import "strings"

const upperHex = "0123456789ABCDEF"

// Encode percent-encodes s. With keepSlash, "/" is left as is (object keys
// and paths); otherwise it is encoded too (query values, SigV4 UriEncode).
func Encode(s string, keepSlash bool) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if unreserved(ch) || (keepSlash && ch == '/') {
			b.WriteByte(ch)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(upperHex[ch>>4])
		b.WriteByte(upperHex[ch&0x0f])
	}
	return b.String()
}

// unreserved reports whether ch is in the RFC 3986 section 2.3 set
// ALPHA / DIGIT / "-" / "." / "_" / "~".
func unreserved(ch byte) bool {
	switch {
	case ch >= 'a' && ch <= 'z', ch >= 'A' && ch <= 'Z', ch >= '0' && ch <= '9':
		return true
	}
	return ch == '-' || ch == '.' || ch == '_' || ch == '~'
}
