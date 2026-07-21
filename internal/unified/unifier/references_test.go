package unifier

import (
	"reflect"
	"testing"

	"github.com/masahiro331/wisteria/pkg/advisory"
)

func TestMergeReferences(t *testing.T) {
	tests := []struct {
		name string
		in   []advisory.Reference
		want []advisory.Reference
	}{
		{
			name: "empty input returns nil",
			in:   nil,
			want: nil,
		},
		{
			name: "single ref kept as-is after normalize",
			in: []advisory.Reference{
				{URL: "https://example.com/a"},
			},
			want: []advisory.Reference{
				{URL: "https://example.com/a"},
			},
		},
		{
			name: "scheme and host lowercased, trailing slash stripped, fragment dropped",
			in: []advisory.Reference{
				{URL: "HTTPS://Example.COM/Path/#frag"},
			},
			want: []advisory.Reference{
				{URL: "https://example.com/Path"},
			},
		},
		{
			name: "duplicate URLs after normalization collapse, tags unioned and sorted",
			in: []advisory.Reference{
				{URL: "https://example.com/a", Tags: []string{"FIX", "WEB"}},
				{URL: "HTTPS://example.com/a/", Tags: []string{"WEB", "ADVISORY"}},
			},
			want: []advisory.Reference{
				{URL: "https://example.com/a", Tags: []string{"ADVISORY", "FIX", "WEB"}},
			},
		},
		{
			name: "lex sort by normalized URL",
			in: []advisory.Reference{
				{URL: "https://z.example.com/"},
				{URL: "https://a.example.com/"},
				{URL: "https://m.example.com/"},
			},
			want: []advisory.Reference{
				{URL: "https://a.example.com"},
				{URL: "https://m.example.com"},
				{URL: "https://z.example.com"},
			},
		},
		{
			name: "tags dedup keeps single copy",
			in: []advisory.Reference{
				{URL: "https://example.com/a", Tags: []string{"FIX", "FIX"}},
			},
			want: []advisory.Reference{
				{URL: "https://example.com/a", Tags: []string{"FIX"}},
			},
		},
		{
			name: "no tags stays nil after merge",
			in: []advisory.Reference{
				{URL: "https://example.com/a"},
				{URL: "https://example.com/a"},
			},
			want: []advisory.Reference{
				{URL: "https://example.com/a"},
			},
		},
		{
			name: "malformed URL passes through unchanged",
			in: []advisory.Reference{
				{URL: "not a url"},
			},
			want: []advisory.Reference{
				{URL: "not a url"},
			},
		},
		{
			name: "root trailing slash also stripped",
			in: []advisory.Reference{
				{URL: "https://example.com/"},
			},
			want: []advisory.Reference{
				{URL: "https://example.com"},
			},
		},
		{
			name: "percent-encoded path byte %2F preserved when trailing slash stripped",
			in: []advisory.Reference{
				{URL: "https://example.com/a%2Fb/"},
			},
			want: []advisory.Reference{
				{URL: "https://example.com/a%2Fb"},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := mergeReferences(tc.in)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("mergeReferences\n got = %#v\nwant = %#v", got, tc.want)
			}
		})
	}
}
