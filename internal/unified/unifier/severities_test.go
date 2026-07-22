package unifier

import (
	"reflect"
	"testing"

	"github.com/masahiro331/wisteria/pkg/advisory"
)

func TestMergeSeverities(t *testing.T) {
	provCVE := advisory.Provenance{Kind: advisory.SourceCVE, Path: "cve/x.json", ID: "CVE-2024-0001"}
	provAlma := advisory.Provenance{Kind: advisory.SourceOSV, Path: "osv/AlmaLinux/ALSA-1.json", ID: "ALSA-1"}
	provGit := advisory.Provenance{Kind: advisory.SourceOSV, Path: "osv/GitHub Reviewed/GHSA-1.json", ID: "GHSA-1"} // Path stays verbatim; tag below is normalized

	tests := []struct {
		name    string
		in      []advisory.Severity
		sources []string // sourceTag of each in[i] (parallel slice; "" if no priority)
		want    []advisory.Severity
	}{
		{
			name: "empty input returns nil",
			in:   nil,
			want: nil,
		},
		{
			name: "single severity passes through",
			in: []advisory.Severity{
				{Type: "CVSS_V3", Vector: "CVSS:3.1/AV:N", Score: "9.8", From: provCVE},
			},
			sources: []string{"cve.mitre"},
			want: []advisory.Severity{
				{Type: "CVSS_V3", Vector: "CVSS:3.1/AV:N", Score: "9.8", From: provCVE},
			},
		},
		{
			name: "same (Type,Vector) collapses, highest priority Provenance wins",
			in: []advisory.Severity{
				{Type: "CVSS_V3", Vector: "CVSS:3.1/AV:N", Score: "9.8", From: provAlma},
				{Type: "CVSS_V3", Vector: "CVSS:3.1/AV:N", Score: "9.8", From: provCVE},
			},
			sources: []string{"osv.AlmaLinux", "cve.mitre"},
			want: []advisory.Severity{
				{Type: "CVSS_V3", Vector: "CVSS:3.1/AV:N", Score: "9.8", From: provCVE},
			},
		},
		{
			name: "different vectors stay parallel",
			in: []advisory.Severity{
				{Type: "CVSS_V3", Vector: "CVSS:3.1/AV:N", Score: "9.8", From: provCVE},
				{Type: "CVSS_V3", Vector: "CVSS:3.1/AV:L", Score: "7.2", From: provAlma},
			},
			sources: []string{"cve.mitre", "osv.AlmaLinux"},
			want: []advisory.Severity{
				{Type: "CVSS_V3", Vector: "CVSS:3.1/AV:N", Score: "9.8", From: provCVE},
				{Type: "CVSS_V3", Vector: "CVSS:3.1/AV:L", Score: "7.2", From: provAlma},
			},
		},
		{
			name: "no Vector falls back to (Type, Score) for dedup",
			in: []advisory.Severity{
				{Type: "CVSS_V2", Score: "7.5", From: provAlma},
				{Type: "CVSS_V2", Score: "7.5", From: provCVE},
			},
			sources: []string{"osv.AlmaLinux", "cve.mitre"},
			want: []advisory.Severity{
				{Type: "CVSS_V2", Score: "7.5", From: provCVE},
			},
		},
		{
			name: "sort by source priority then by Type",
			in: []advisory.Severity{
				{Type: "CVSS_V3", Vector: "v3", Score: "9.8", From: provGit},
				{Type: "CVSS_V2", Vector: "v2", Score: "7.5", From: provCVE},
				{Type: "CVSS_V4", Vector: "v4", Score: "9.0", From: provAlma},
			},
			sources: []string{"osv.GitHub_Reviewed", "cve.mitre", "osv.AlmaLinux"},
			// cve.mitre (rank 0) → osv.AlmaLinux (rank 2) → osv.GitHub_Reviewed (later)
			want: []advisory.Severity{
				{Type: "CVSS_V2", Vector: "v2", Score: "7.5", From: provCVE},
				{Type: "CVSS_V4", Vector: "v4", Score: "9.0", From: provAlma},
				{Type: "CVSS_V3", Vector: "v3", Score: "9.8", From: provGit},
			},
		},
		{
			name: "Vector vs no-Vector for same Type are not collapsed",
			in: []advisory.Severity{
				{Type: "CVSS_V3", Vector: "v3", Score: "9.8", From: provCVE},
				{Type: "CVSS_V3", Score: "9.8", From: provAlma},
			},
			sources: []string{"cve.mitre", "osv.AlmaLinux"},
			want: []advisory.Severity{
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
			in: []advisory.Severity{
				{Type: "CVSS_V3", Vector: "CVSS:3.1/AV:N", Score: "9.8", From: provCVE},
				{Type: "CVSS_V3", Vector: "CVSS:3.0/AV:N", Score: "9.8", From: provCVE},
			},
			sources: []string{"cve.mitre", "cve.mitre"},
			want: []advisory.Severity{
				{Type: "CVSS_V3", Vector: "CVSS:3.0/AV:N", Score: "9.8", From: provCVE},
				{Type: "CVSS_V3", Vector: "CVSS:3.1/AV:N", Score: "9.8", From: provCVE},
			},
		},
		{
			// Same source rank (both unranked) and same Type with
			// distinct (Vector,Score). Score is the final tie-breaker.
			name: "same Type no Vector falls back to Score for ordering",
			in: []advisory.Severity{
				{Type: "CVSS_V2", Score: "9.0", From: provAlma},
				{Type: "CVSS_V2", Score: "7.5", From: provAlma},
			},
			sources: []string{"osv.AlmaLinux", "osv.AlmaLinux"},
			want: []advisory.Severity{
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

// TestMergeSeverities_FillsScoreFromVector pins the uniformity rule:
// every CVSS assessment carries a base score, whichever source asserted
// it. OSV entries arrive with only the vector (OSV `score` is the
// vector string); the merge computes the missing number. Non-CVSS
// values (Ubuntu's rating words) and source-asserted scores are left
// untouched.
func TestMergeSeverities_FillsScoreFromVector(t *testing.T) {
	prov := advisory.Provenance{Kind: advisory.SourceOSV, Path: "osv/PyPI/PYSEC-1.json", ID: "PYSEC-1"}

	tests := []struct {
		name string
		in   advisory.Severity
		want string // expected Score after merge
	}{
		{
			name: "CVSS v3.1 vector",
			in:   advisory.Severity{Type: "CVSS_V3", Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", From: prov},
			want: "9.8",
		},
		{
			name: "CVSS v3.0 vector",
			in:   advisory.Severity{Type: "CVSS_V3", Vector: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", From: prov},
			want: "9.8",
		},
		{
			name: "CVSS v4.0 vector",
			in:   advisory.Severity{Type: "CVSS_V4", Vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", From: prov},
			want: "9.3",
		},
		{
			name: "CVSS v2 vector (no CVSS: prefix upstream)",
			in:   advisory.Severity{Type: "CVSS_V2", Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P", From: prov},
			want: "7.5",
		},
		{
			name: "source-asserted score is preserved",
			in:   advisory.Severity{Type: "CVSS_V3", Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", Score: "9.9", From: prov},
			want: "9.9",
		},
		{
			name: "non-CVSS rating word stays untouched",
			in:   advisory.Severity{Type: "Ubuntu", Vector: "medium", From: prov},
			want: "",
		},
		{
			name: "malformed CVSS vector stays untouched",
			in:   advisory.Severity{Type: "CVSS_V3", Vector: "CVSS:3.1/garbage", From: prov},
			want: "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := mergeSeverities([]severityItem{{Severity: tc.in, source: "osv.PyPI"}})
			if len(got) != 1 {
				t.Fatalf("merged to %d entries", len(got))
			}
			if got[0].Score != tc.want {
				t.Errorf("Score = %q, want %q", got[0].Score, tc.want)
			}
			if got[0].Vector != tc.in.Vector {
				t.Errorf("Vector changed: %q", got[0].Vector)
			}
		})
	}
}
