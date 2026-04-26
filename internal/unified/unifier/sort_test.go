package unifier

import (
	"cmp"
	"reflect"
	"testing"
)

// item is a tiny test fixture for stableSortByPriority. The real callers
// (descriptions / affected / severities) supply their own element types
// and lessSecondary closures; this test exercises the helper in
// isolation so we know the priority + secondary + input-index tie-break
// chain is correct independent of any merge function.
type item struct {
	source string
	key    string
	tag    string
}

func TestStableSortByPriority(t *testing.T) {
	tests := []struct {
		name string
		in   []item
		want []item
	}{
		{
			name: "empty input returns nil",
			in:   nil,
			want: nil,
		},
		{
			name: "single element passes through",
			in:   []item{{source: "cve.mitre", key: "a", tag: "x"}},
			want: []item{{source: "cve.mitre", key: "a", tag: "x"}},
		},
		{
			// Higher-priority source comes first regardless of secondary
			// key — this is the §8.1 vendor priority gate.
			name: "priority dominates secondary key",
			in: []item{
				{source: "osv.AlmaLinux", key: "a", tag: "alma-a"},
				{source: "cve.mitre", key: "z", tag: "cve-z"},
			},
			want: []item{
				{source: "cve.mitre", key: "z", tag: "cve-z"},
				{source: "osv.AlmaLinux", key: "a", tag: "alma-a"},
			},
		},
		{
			// Within one source bucket, secondary key sorts ascending.
			name: "secondary key sorts within same source",
			in: []item{
				{source: "osv.AlmaLinux", key: "ja", tag: "alma-ja"},
				{source: "osv.AlmaLinux", key: "en", tag: "alma-en"},
			},
			want: []item{
				{source: "osv.AlmaLinux", key: "en", tag: "alma-en"},
				{source: "osv.AlmaLinux", key: "ja", tag: "alma-ja"},
			},
		},
		{
			// Same source + same secondary key → preserve input order.
			// This is what keeps OSV Summary-then-Details stable.
			name: "input index breaks ties",
			in: []item{
				{source: "osv.AlmaLinux", key: "en", tag: "first"},
				{source: "osv.AlmaLinux", key: "en", tag: "second"},
				{source: "osv.AlmaLinux", key: "en", tag: "third"},
			},
			want: []item{
				{source: "osv.AlmaLinux", key: "en", tag: "first"},
				{source: "osv.AlmaLinux", key: "en", tag: "second"},
				{source: "osv.AlmaLinux", key: "en", tag: "third"},
			},
		},
		{
			// Unranked source (not in sourcePriority) lands after every
			// ranked source via PriorityRank's len(...) fallback.
			name: "unranked source sorts last",
			in: []item{
				{source: "osv.unknown", key: "a", tag: "unk"},
				{source: "cve.mitre", key: "z", tag: "cve"},
			},
			want: []item{
				{source: "cve.mitre", key: "z", tag: "cve"},
				{source: "osv.unknown", key: "a", tag: "unk"},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := stableSortByPriority(
				tc.in,
				func(it item) string { return it.source },
				func(a, b item) int { return cmp.Compare(a.key, b.key) },
			)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("stableSortByPriority\n got = %#v\nwant = %#v", got, tc.want)
			}
		})
	}
}
