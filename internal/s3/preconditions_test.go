package s3

import "testing"

// Write preconditions per RFC 9110 13.1.1 (If-Match: the current ETag or
// "*" for any existing object) and 13.1.2 (If-None-Match: "*" fails when the
// object exists, the conditional-create used by S3 clients).
func TestWritePreconditionsHold(t *testing.T) {
	cases := []struct {
		ifNone, ifMatch string
		exists          bool
		etag            string
		want            bool
	}{
		{"", "", false, "", true},
		{"*", "", false, "", true},
		{"*", "", true, "abc", false},
		{"", "*", true, "abc", true},
		{"", "*", false, "", false},
		{"", `"abc"`, true, "abc", true},
		{"", `"xyz"`, true, "abc", false},
		{"", `"abc"`, false, "", false},
		{"*", `"abc"`, true, "abc", false},
	}
	for _, c := range cases {
		if got := writePreconditionsHold(c.ifNone, c.ifMatch, c.exists, c.etag); got != c.want {
			t.Errorf("ifNone=%q ifMatch=%q exists=%v etag=%q: got %v, want %v", c.ifNone, c.ifMatch, c.exists, c.etag, got, c.want)
		}
	}
}
