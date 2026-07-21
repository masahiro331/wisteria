package unifier

import (
	"reflect"
	"testing"

	"github.com/masahiro331/wisteria/pkg/advisory"
)

func TestMergeDescriptions(t *testing.T) {
	provCVE := advisory.Provenance{Kind: advisory.SourceCVE, Path: "cve/x.json", ID: "CVE-2024-0001"}
	provAlma := advisory.Provenance{Kind: advisory.SourceOSV, Path: "osv/AlmaLinux/ALSA-1.json", ID: "ALSA-1"}
	provGit := advisory.Provenance{Kind: advisory.SourceOSV, Path: "osv/GitHub Reviewed/GHSA-1.json", ID: "GHSA-1"}

	tests := []struct {
		name    string
		in      []advisory.Description
		sources []string
		want    []advisory.Description
	}{
		{
			name: "empty input returns nil",
			in:   nil,
			want: nil,
		},
		{
			name: "single description passes through",
			in: []advisory.Description{
				{Lang: "en", Text: "summary", From: provCVE},
			},
			sources: []string{"cve.mitre"},
			want: []advisory.Description{
				{Lang: "en", Text: "summary", From: provCVE},
			},
		},
		{
			// §8.3: parallel hold (no merge); sort by priority then lang.
			name: "sort by source priority then lang alphabetically",
			in: []advisory.Description{
				{Lang: "ja", Text: "JP", From: provAlma},
				{Lang: "en", Text: "GH-en", From: provGit},
				{Lang: "en", Text: "CVE-en", From: provCVE},
				{Lang: "en", Text: "Alma-en", From: provAlma},
			},
			sources: []string{"osv.AlmaLinux", "osv.GitHub_Reviewed", "cve.mitre", "osv.AlmaLinux"},
			want: []advisory.Description{
				// cve.mitre (rank 0)
				{Lang: "en", Text: "CVE-en", From: provCVE},
				// osv.AlmaLinux (rank 2): en before ja
				{Lang: "en", Text: "Alma-en", From: provAlma},
				{Lang: "ja", Text: "JP", From: provAlma},
				// osv.GitHub_Reviewed (rank 8)
				{Lang: "en", Text: "GH-en", From: provGit},
			},
		},
		{
			// OSV Summary + Details are kept as separate descriptions
			// (§8.3 parallel-hold rule): same source, same lang, distinct
			// text must remain. Tie-break by input index keeps Summary
			// first.
			name: "same source same lang preserves both entries in input order",
			in: []advisory.Description{
				{Lang: "en", Text: "Summary line", From: provAlma},
				{Lang: "en", Text: "Detailed body of the advisory.", From: provAlma},
			},
			sources: []string{"osv.AlmaLinux", "osv.AlmaLinux"},
			want: []advisory.Description{
				{Lang: "en", Text: "Summary line", From: provAlma},
				{Lang: "en", Text: "Detailed body of the advisory.", From: provAlma},
			},
		},
		{
			// CVE5 CNA + ADP (CISA Vulnrichment etc.) both contribute
			// descriptions. They share source tag (cve.mitre) but the
			// Provenance.ID differs (e.g. CVE-2024-0001 vs
			// CVE-2024-0001#adp:cisa) so they appear as parallel items.
			name: "CVE CNA and ADP descriptions both retained",
			in: []advisory.Description{
				{Lang: "en", Text: "CNA text", From: provCVE},
				{Lang: "en", Text: "ADP text", From: advisory.Provenance{Kind: advisory.SourceCVE, Path: provCVE.Path, ID: "CVE-2024-0001#adp:cisa"}},
			},
			sources: []string{"cve.mitre", "cve.mitre"},
			want: []advisory.Description{
				{Lang: "en", Text: "CNA text", From: provCVE},
				{Lang: "en", Text: "ADP text", From: advisory.Provenance{Kind: advisory.SourceCVE, Path: provCVE.Path, ID: "CVE-2024-0001#adp:cisa"}},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			items := make([]descriptionItem, len(tc.in))
			for i, d := range tc.in {
				src := ""
				if i < len(tc.sources) {
					src = tc.sources[i]
				}
				items[i] = descriptionItem{Description: d, source: src}
			}
			got := mergeDescriptions(items)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("mergeDescriptions\n got = %#v\nwant = %#v", got, tc.want)
			}
		})
	}
}
