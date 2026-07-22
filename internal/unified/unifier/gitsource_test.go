package unifier

import (
	"context"
	"testing"

	"github.com/masahiro331/wisteria/internal/unified"
	"github.com/masahiro331/wisteria/pkg/advisory"
)

// TestMergePrimary_GITContributesAffectedOnly pins the §8.9 contribution
// limit for osv.dev's GIT bucket (CVE→OSV conversions): its unique value
// is the structured git commit ranges in affected[], while its prose
// (description/references/severity/cwe_ids) is transcribed from the CVE
// record we already ingest directly — merging that would duplicate every
// CVE5 text and pollute provenance.
func TestMergePrimary_GITContributesAffectedOnly(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "osv/GIT/CVE-2024-0001.json", `{
		"id":"CVE-2024-0001",
		"summary":"transcribed summary",
		"details":"transcribed details",
		"modified":"2026-01-01T00:00:00Z",
		"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
		"references":[{"type":"WEB","url":"https://example.com/git-only-ref"}],
		"affected":[{
			"ranges":[{"type":"GIT","repo":"https://github.com/x/y",
				"events":[{"introduced":"0"},{"fixed":"f5292a3f6adc"}]}]
		}],
		"database_specific":{"cwe_ids":["CWE-79"]}
	}`)
	writeFixture(t, root, "cve/cvelistV5-main/cves/2024/0xxx/CVE-2024-0001.json", `{
		"cveMetadata":{"cveId":"CVE-2024-0001","dateUpdated":"2024-05-01T00:00:00.000Z"},
		"containers":{"cna":{"descriptions":[{"lang":"en","value":"CNA text"}]}}
	}`)
	entries := []unified.IndexEntry{
		{Path: "osv/GIT/CVE-2024-0001.json", Kind: advisory.SourceOSV, Source: "GIT", SourceID: "CVE-2024-0001"},
		{Path: "cve/cvelistV5-main/cves/2024/0xxx/CVE-2024-0001.json", Kind: advisory.SourceCVE, SourceID: "CVE-2024-0001"},
	}

	rec, err := MergePrimary(context.Background(), root, "CVE-2024-0001", entries)
	if err != nil {
		t.Fatalf("MergePrimary: %v", err)
	}

	// Affected: the git ranges DO land.
	gitAffected := 0
	for _, a := range rec.Affected {
		if a.From.Path == "osv/GIT/CVE-2024-0001.json" {
			gitAffected++
		}
	}
	if gitAffected != 1 {
		t.Errorf("GIT affected entries = %d, want 1", gitAffected)
	}

	// Prose does NOT land.
	for _, d := range rec.Descriptions {
		if d.From.Kind == advisory.SourceOSV {
			t.Errorf("GIT description leaked into merge: %+v", d)
		}
	}
	for _, r := range rec.References {
		if r.URL == "https://example.com/git-only-ref" {
			t.Error("GIT reference leaked into merge")
		}
	}
	for _, s := range rec.Severities {
		if s.From.Kind == advisory.SourceOSV {
			t.Errorf("GIT severity leaked into merge: %+v", s)
		}
	}
	for _, w := range rec.Weaknesses {
		if w.From.Kind == advisory.SourceOSV {
			t.Errorf("GIT weakness leaked into merge: %+v", w)
		}
	}

	// Dates: GIT's conversion timestamps must not move Modified.
	if got := rec.Modified.Year(); got != 2024 {
		t.Errorf("Modified year = %d, want 2024 (GIT's 2026 conversion timestamp must be ignored)", got)
	}

	// Provenance trail keeps the GIT entry.
	gitProv := false
	for _, p := range rec.Provenances {
		if p.Path == "osv/GIT/CVE-2024-0001.json" {
			gitProv = true
		}
	}
	if !gitProv {
		t.Error("GIT provenance entry missing")
	}
}
