package webui

import "testing"

// TestSafeNextRejectsOffSiteTargets covers redirect targets that browsers
// resolve to another host. Per the WHATWG URL standard, "\" acts as "/" for
// special schemes and ASCII tab/newline characters are stripped, so these
// values turn into a scheme-relative "//host" URL.
func TestSafeNextRejectsOffSiteTargets(t *testing.T) {
	hostile := []string{
		"//evil.example",
		"/\\evil.example",
		"\\\\evil.example",
		"/\\/evil.example",
		"/\t/evil.example",
		"/\n/evil.example",
		"/\r/evil.example",
		"https://evil.example//evil.example/x",
		"https://evil.example/\\evil.example",
		"javascript:alert(1)",
		"evil.example",
		"/login?next=//evil.example",
	}
	for _, v := range hostile {
		if got := safeNext(v); got != "/" {
			t.Errorf("safeNext(%q) = %q, want %q", v, got, "/")
		}
	}
}

func TestSafeNextKeepsLocalPaths(t *testing.T) {
	cases := map[string]string{
		"":                                  "/",
		"/files?bucket=a":                   "/files?bucket=a",
		"/settings":                         "/settings",
		"https://console.example/files?x=1": "/files?x=1",
	}
	for in, want := range cases {
		if got := safeNext(in); got != want {
			t.Errorf("safeNext(%q) = %q, want %q", in, got, want)
		}
	}
}
