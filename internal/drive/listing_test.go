package drive

import (
	"slices"
	"testing"
)

func pageKeys(r *ListResult) []string {
	var keys []string
	i, j := 0, 0
	for i < len(r.Objects) || j < len(r.CommonPrefixes) {
		if j >= len(r.CommonPrefixes) || (i < len(r.Objects) && r.Objects[i].Key < r.CommonPrefixes[j]) {
			keys = append(keys, r.Objects[i].Key)
			i++
		} else {
			keys = append(keys, r.CommonPrefixes[j]+"(p)")
			j++
		}
	}
	return keys
}

func objs(keys ...string) []Object {
	out := make([]Object, len(keys))
	for i, k := range keys {
		out[i] = Object{Key: k}
	}
	return out
}

// AGENTS.md: listings order objects and common prefixes together by key, so
// a page that ends at "a/" still returns "a.txt" on the next page.
func TestPageListingInterleavesObjectsAndPrefixes(t *testing.T) {
	objects := objs("b.txt", "a.txt", "c")
	prefixes := []string{"a/", "b/"}

	first := pageListing(objects, prefixes, "", "/", 2)
	if got := pageKeys(first); !slices.Equal(got, []string{"a.txt", "a/(p)"}) || !first.IsTruncated || first.NextAfter != "a/" {
		t.Fatalf("page 1 = %v truncated=%v next=%q", got, first.IsTruncated, first.NextAfter)
	}
	second := pageListing(objects, prefixes, first.NextAfter, "/", 2)
	if got := pageKeys(second); !slices.Equal(got, []string{"b.txt", "b/(p)"}) || !second.IsTruncated {
		t.Fatalf("page 2 = %v truncated=%v", got, second.IsTruncated)
	}
	third := pageListing(objects, prefixes, second.NextAfter, "/", 2)
	if got := pageKeys(third); !slices.Equal(got, []string{"c"}) || third.IsTruncated {
		t.Fatalf("page 3 = %v truncated=%v", got, third.IsTruncated)
	}
}

func TestGroupByDelimiter(t *testing.T) {
	direct, prefixes := groupByDelimiter(objs("p/a", "p/x|1", "p/x|2", "p/y|z|1"), "p/", "|")
	keys := make([]string, len(direct))
	for i, o := range direct {
		keys[i] = o.Key
	}
	if !slices.Equal(keys, []string{"p/a"}) || !slices.Equal(prefixes, []string{"p/x|", "p/y|"}) {
		t.Fatalf("direct=%v prefixes=%v", keys, prefixes)
	}
}
