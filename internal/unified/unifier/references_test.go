package unifier

import (
	"reflect"
	"testing"

	"github.com/masahiro331/wisteria/internal/unified"
)

func TestMergeReferences(t *testing.T) {
	tests := []struct {
		name string
		in   []unified.Reference
		want []unified.Reference
	}{
		{
			name: "empty input returns nil",
			in:   nil,
			want: nil,
		},
		{
			name: "single ref kept as-is after normalize",
			in: []unified.Reference{
				{URL: "https://example.com/a"},
			},
			want: []unified.Reference{
				{URL: "https://example.com/a"},
			},
		},
		{
			name: "scheme and host lowercased, trailing slash stripped, fragment dropped",
			in: []unified.Reference{
				{URL: "HTTPS://Example.COM/Path/#frag"},
			},
			want: []unified.Reference{
				{URL: "https://example.com/Path"},
			},
		},
		{
			name: "duplicate URLs after normalization collapse, tags unioned and sorted",
			in: []unified.Reference{
				{URL: "https://example.com/a", Tags: []string{"FIX", "WEB"}},
				{URL: "HTTPS://example.com/a/", Tags: []string{"WEB", "ADVISORY"}},
			},
			want: []unified.Reference{
				{URL: "https://example.com/a", Tags: []string{"ADVISORY", "FIX", "WEB"}},
			},
		},
		{
			name: "lex sort by normalized URL",
			in: []unified.Reference{
				{URL: "https://z.example.com/"},
				{URL: "https://a.example.com/"},
				{URL: "https://m.example.com/"},
			},
			want: []unified.Reference{
				{URL: "https://a.example.com"},
				{URL: "https://m.example.com"},
				{URL: "https://z.example.com"},
			},
		},
		{
			name: "tags dedup keeps single copy",
			in: []unified.Reference{
				{URL: "https://example.com/a", Tags: []string{"FIX", "FIX"}},
			},
			want: []unified.Reference{
				{URL: "https://example.com/a", Tags: []string{"FIX"}},
			},
		},
		{
			name: "no tags stays nil after merge",
			in: []unified.Reference{
				{URL: "https://example.com/a"},
				{URL: "https://example.com/a"},
			},
			want: []unified.Reference{
				{URL: "https://example.com/a"},
			},
		},
		{
			name: "malformed URL passes through unchanged",
			in: []unified.Reference{
				{URL: "not a url"},
			},
			want: []unified.Reference{
				{URL: "not a url"},
			},
		},
		{
			name: "root trailing slash also stripped",
			in: []unified.Reference{
				{URL: "https://example.com/"},
			},
			want: []unified.Reference{
				{URL: "https://example.com"},
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
