package unifier

import (
	"reflect"
	"testing"

	"github.com/masahiro331/wisteria/internal/unified"
)

func TestMergeSeverities(t *testing.T) {
	provCVE := unified.Provenance{Kind: unified.SourceCVE, Path: "cve/x.json", ID: "CVE-2024-0001"}
	provAlma := unified.Provenance{Kind: unified.SourceOSV, Path: "osv/AlmaLinux/ALSA-1.json", ID: "ALSA-1"}
	provGit := unified.Provenance{Kind: unified.SourceOSV, Path: "osv/GitHub Reviewed/GHSA-1.json", ID: "GHSA-1"} // Path stays verbatim; tag below is normalized

	tests := []struct {
		name    string
		in      []unified.Severity
		sources []string // sourceTag of each in[i] (parallel slice; "" if no priority)
		want    []unified.Severity
	}{
		{
			name: "empty input returns nil",
			in:   nil,
			want: nil,
		},
		{
			name: "single severity passes through",
			in: []unified.Severity{
				{Type: "CVSS_V3", Vector: "CVSS:3.1/AV:N", Score: "9.8", From: provCVE},
			},
			sources: []string{"cve.mitre"},
			want: []unified.Severity{
				{Type: "CVSS_V3", Vector: "CVSS:3.1/AV:N", Score: "9.8", From: provCVE},
			},
		},
		{
			name: "same (Type,Vector) collapses, highest priority Provenance wins",
			in: []unified.Severity{
				{Type: "CVSS_V3", Vector: "CVSS:3.1/AV:N", Score: "9.8", From: provAlma},
				{Type: "CVSS_V3", Vector: "CVSS:3.1/AV:N", Score: "9.8", From: provCVE},
			},
			sources: []string{"osv.AlmaLinux", "cve.mitre"},
			want: []unified.Severity{
				{Type: "CVSS_V3", Vector: "CVSS:3.1/AV:N", Score: "9.8", From: provCVE},
			},
		},
		{
			name: "different vectors stay parallel",
			in: []unified.Severity{
				{Type: "CVSS_V3", Vector: "CVSS:3.1/AV:N", Score: "9.8", From: provCVE},
				{Type: "CVSS_V3", Vector: "CVSS:3.1/AV:L", Score: "7.2", From: provAlma},
			},
			sources: []string{"cve.mitre", "osv.AlmaLinux"},
			want: []unified.Severity{
				{Type: "CVSS_V3", Vector: "CVSS:3.1/AV:N", Score: "9.8", From: provCVE},
				{Type: "CVSS_V3", Vector: "CVSS:3.1/AV:L", Score: "7.2", From: provAlma},
			},
		},
		{
			name: "no Vector falls back to (Type, Score) for dedup",
			in: []unified.Severity{
				{Type: "CVSS_V2", Score: "7.5", From: provAlma},
				{Type: "CVSS_V2", Score: "7.5", From: provCVE},
			},
			sources: []string{"osv.AlmaLinux", "cve.mitre"},
			want: []unified.Severity{
				{Type: "CVSS_V2", Score: "7.5", From: provCVE},
			},
		},
		{
			name: "sort by source priority then by Type",
			in: []unified.Severity{
				{Type: "CVSS_V3", Vector: "v3", Score: "9.8", From: provGit},
				{Type: "CVSS_V2", Vector: "v2", Score: "7.5", From: provCVE},
				{Type: "CVSS_V4", Vector: "v4", Score: "9.0", From: provAlma},
			},
			sources: []string{"osv.GitHub_Reviewed", "cve.mitre", "osv.AlmaLinux"},
			// cve.mitre (rank 0) → osv.AlmaLinux (rank 2) → osv.GitHub_Reviewed (later)
			want: []unified.Severity{
				{Type: "CVSS_V2", Vector: "v2", Score: "7.5", From: provCVE},
				{Type: "CVSS_V4", Vector: "v4", Score: "9.0", From: provAlma},
				{Type: "CVSS_V3", Vector: "v3", Score: "9.8", From: provGit},
			},
		},
		{
			name: "Vector vs no-Vector for same Type are not collapsed",
			in: []unified.Severity{
				{Type: "CVSS_V3", Vector: "v3", Score: "9.8", From: provCVE},
				{Type: "CVSS_V3", Score: "9.8", From: provAlma},
			},
			sources: []string{"cve.mitre", "osv.AlmaLinux"},
			want: []unified.Severity{
				{Type: "CVSS_V3", Vector: "v3", Score: "9.8", From: provCVE},
				{Type: "CVSS_V3", Score: "9.8", From: provAlma},
			},
		},
		{
			// Reproducer for the round-2 Codex finding: when source rank
			// and Type tie (one CVE5 file emitting both cvssV3_0 and
			// cvssV3_1), the comparator must still pick a stable order
			// so the JSON output is reproducible across runs.
			name: "same source+Type with different Vectors sorts by Vector",
			in: []unified.Severity{
				{Type: "CVSS_V3", Vector: "CVSS:3.1/AV:N", Score: "9.8", From: provCVE},
				{Type: "CVSS_V3", Vector: "CVSS:3.0/AV:N", Score: "9.8", From: provCVE},
			},
			sources: []string{"cve.mitre", "cve.mitre"},
			want: []unified.Severity{
				{Type: "CVSS_V3", Vector: "CVSS:3.0/AV:N", Score: "9.8", From: provCVE},
				{Type: "CVSS_V3", Vector: "CVSS:3.1/AV:N", Score: "9.8", From: provCVE},
			},
		},
		{
			// Same source rank (both unranked) and same Type with
			// distinct (Vector,Score). Score is the final tie-breaker.
			name: "same Type no Vector falls back to Score for ordering",
			in: []unified.Severity{
				{Type: "CVSS_V2", Score: "9.0", From: provAlma},
				{Type: "CVSS_V2", Score: "7.5", From: provAlma},
			},
			sources: []string{"osv.AlmaLinux", "osv.AlmaLinux"},
			want: []unified.Severity{
				{Type: "CVSS_V2", Score: "7.5", From: provAlma},
				{Type: "CVSS_V2", Score: "9.0", From: provAlma},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			items := make([]severityItem, len(tc.in))
			for i, s := range tc.in {
				src := ""
				if i < len(tc.sources) {
					src = tc.sources[i]
				}
				items[i] = severityItem{Severity: s, source: src}
			}
			got := mergeSeverities(items)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("mergeSeverities\n got = %#v\nwant = %#v", got, tc.want)
			}
		})
	}
}
