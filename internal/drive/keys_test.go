package drive

import (
	"sort"
	"strings"
	"testing"

	"s3drive/internal/google"
)

func TestEscapeSegmentsRoundTrip(t *testing.T) {
	cases := []string{"", ".", "..", "~s3drive~literal", "normal", "ünïcode", "a b"}
	for _, in := range cases {
		disk := encodeSegment(in)
		if got := decodeSegment(disk); got != in {
			t.Fatalf("round trip %q -> %q -> %q", in, disk, got)
		}
	}
	if encodeSegment("normal") != "normal" {
		t.Fatal("ordinary names must not be escaped")
	}
	if !strings.HasPrefix(encodeSegment(""), segEscape) {
		t.Fatal("empty segment must be escaped")
	}
}

func TestValidateKey(t *testing.T) {
	if err := ValidateKey("photos/2026/cat.jpg"); err != nil {
		t.Fatalf("valid key rejected: %v", err)
	}
	if err := ValidateKey(""); err == nil {
		t.Fatal("empty key accepted")
	}
	if err := ValidateKey(strings.Repeat("a", 1025)); err == nil {
		t.Fatal("overlong key accepted")
	}
	if err := ValidateKey("ok/" + strings.Repeat("b", 256)); err == nil {
		t.Fatal("overlong path segment accepted")
	}
	if err := ValidateKey("bad\x00key"); err == nil {
		t.Fatal("NUL byte accepted")
	}
	if err := ValidateKey(strings.Repeat("a", 255)); err != nil {
		t.Fatalf("255-byte segment rejected: %v", err)
	}
	// Escaping expands a segment that begins with the private prefix. Drive's
	// 255-byte name limit applies to the encoded name, not the S3 key.
	expanding := segEscape + strings.Repeat("x", 200)
	if len(expanding) <= 255 && len(encodeSegment(expanding)) > 255 {
		if err := ValidateKey(expanding); err == nil {
			t.Fatal("segment exceeding Drive's encoded limit accepted")
		}
	}
}

func TestListSortNameOrdersFileFolderAndNeighbour(t *testing.T) {
	files := []google.File{
		{Name: "a0"},
		{Name: "a", IsFolder: true},
		{Name: "a.txt"},
	}
	sort.SliceStable(files, func(i, j int) bool {
		return listSortName(&files[i]) < listSortName(&files[j])
	})
	got := []string{listSortName(&files[0]), listSortName(&files[1]), listSortName(&files[2])}
	want := []string{"a.txt", "a/", "a0"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("list order = %v, want %v", got, want)
		}
	}
}

func TestPastAfterSkipsWholeCommonPrefix(t *testing.T) {
	cases := []struct {
		key, after, delimiter string
		want                  bool
	}{
		{"a/b", "a/", "/", false},
		{"a0", "a/", "/", true},
		{"a/", "a.txt", "/", true},
		{"a/", "a/0", "/", false},
		{"b", "a", "", true},
		{"a", "a", "", false},
	}
	for _, tc := range cases {
		if got := pastAfter(tc.key, tc.after, tc.delimiter); got != tc.want {
			t.Errorf("pastAfter(%q, %q, %q) = %v, want %v", tc.key, tc.after, tc.delimiter, got, tc.want)
		}
	}
}

func TestSplitKeyAndPrefix(t *testing.T) {
	dirs, name, err := splitKey("a/b/c.txt")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(dirs, "/") != "a/b" || name != "c.txt" {
		t.Fatalf("splitKey = %v %q", dirs, name)
	}
	dirs, name, err = splitKey("single")
	if err != nil || len(dirs) != 0 || name != "single" {
		t.Fatalf("single splitKey = %v %q %v", dirs, name, err)
	}
	if _, _, err := splitKey(""); err == nil {
		t.Fatal("empty splitKey accepted")
	}

	dirs, name, err = splitPrefix("a/b/")
	if err != nil || strings.Join(dirs, "/") != "a/b" || name != "" {
		t.Fatalf("directory prefix = %v %q %v", dirs, name, err)
	}
	dirs, name, err = splitPrefix("a/b/c")
	if err != nil || strings.Join(dirs, "/") != "a/b" || name != "c" {
		t.Fatalf("name prefix = %v %q %v", dirs, name, err)
	}
}
