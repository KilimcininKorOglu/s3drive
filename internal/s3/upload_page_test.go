package s3

import (
	"slices"
	"testing"

	"s3drive/internal/store"
)

func uploadKeys(out listMultipartUploadsResult) (keys, prefixes []string) {
	for _, u := range out.Uploads {
		keys = append(keys, u.Key+"#"+u.UploadID)
	}
	for _, p := range out.CommonPrefixes {
		prefixes = append(prefixes, p.Prefix)
	}
	return keys, prefixes
}

// ListMultipartUploads semantics: uploads after (key-marker, upload-id-marker)
// in key/ID order, keys containing the delimiter rolled up into common
// prefixes once, truncation at max-uploads.
func TestUploadPageFill(t *testing.T) {
	uploads := []*store.Upload{
		{Key: "a", ID: "1"}, {Key: "a", ID: "2"}, {Key: "b", ID: "1"},
		{Key: "dir/x", ID: "1"}, {Key: "dir/y", ID: "1"}, {Key: "z", ID: "1"},
	}
	cases := []struct {
		name           string
		page           uploadPage
		keys, prefixes []string
		truncated      bool
	}{
		{"all", uploadPage{max: 1000}, []string{"a#1", "a#2", "b#1", "dir/x#1", "dir/y#1", "z#1"}, nil, false},
		{"key marker only skips the whole key", uploadPage{keyMarker: "a", max: 1000}, []string{"b#1", "dir/x#1", "dir/y#1", "z#1"}, nil, false},
		{"upload id marker resumes inside a key", uploadPage{keyMarker: "a", uploadMarker: "1", max: 1000}, []string{"a#2", "b#1", "dir/x#1", "dir/y#1", "z#1"}, nil, false},
		{"delimiter groups once", uploadPage{delimiter: "/", max: 1000}, []string{"a#1", "a#2", "b#1", "z#1"}, []string{"dir/"}, false},
		{"marker inside a group skips it", uploadPage{delimiter: "/", keyMarker: "dir/x", max: 1000}, []string{"z#1"}, nil, false},
		{"prefix", uploadPage{prefix: "dir/", max: 1000}, []string{"dir/x#1", "dir/y#1"}, nil, false},
		{"truncate", uploadPage{max: 2}, []string{"a#1", "a#2"}, nil, true},
		{"zero max", uploadPage{max: 0}, nil, nil, true},
	}
	for _, c := range cases {
		var out listMultipartUploadsResult
		c.page.fill(&out, uploads)
		keys, prefixes := uploadKeys(out)
		if !slices.Equal(keys, c.keys) || !slices.Equal(prefixes, c.prefixes) || out.IsTruncated != c.truncated {
			t.Errorf("%s: keys=%v prefixes=%v truncated=%v, want %v %v %v", c.name, keys, prefixes, out.IsTruncated, c.keys, c.prefixes, c.truncated)
		}
	}
}
