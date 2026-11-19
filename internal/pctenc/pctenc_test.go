package pctenc

import "testing"

// Expected values follow RFC 3986 (2.1: upper-case hex; 2.3: unreserved set)
// and the AWS SigV4 UriEncode rules (UTF-8 bytes encoded one by one, "/"
// encoded except in object key paths).
func TestEncode(t *testing.T) {
	cases := []struct {
		in        string
		keepSlash bool
		want      string
	}{
		{"AZaz09-._~", false, "AZaz09-._~"},
		{"a b", false, "a%20b"},
		{"a/b", false, "a%2Fb"},
		{"a/b", true, "a/b"},
		{"é", false, "%C3%A9"},
		{"+=&?#%", true, "%2B%3D%26%3F%23%25"},
		{"\x00\x7f\xff", false, "%00%7F%FF"},
		{"", false, ""},
	}
	for _, c := range cases {
		if got := Encode(c.in, c.keepSlash); got != c.want {
			t.Errorf("Encode(%q, %v) = %q, want %q", c.in, c.keepSlash, got, c.want)
		}
	}
}
