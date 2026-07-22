package unifier

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/masahiro331/wisteria/internal/unified"
	"github.com/masahiro331/wisteria/pkg/advisory"
)

func writeFixture(t *testing.T, root, rel, body string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestMergePrimary_MergesDates pins the date rule: Published is the
// earliest any source published the advisory, Modified the latest any
// source touched it — one uniform pair regardless of which sources
// contributed.
func TestMergePrimary_MergesDates(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "osv/PyPI/PYSEC-2024-1.json",
		`{"id":"PYSEC-2024-1","aliases":["CVE-2024-0001"],`+
			`"published":"2024-02-01T00:00:00Z","modified":"2024-06-01T00:00:00Z"}`)
	writeFixture(t, root, "cve/cvelistV5-main/cves/2024/0xxx/CVE-2024-0001.json",
		`{"cveMetadata":{"cveId":"CVE-2024-0001",`+
			`"datePublished":"2024-01-15T00:00:00.000Z","dateUpdated":"2024-05-01T00:00:00.000Z"},`+
			`"containers":{"cna":{}}}`)
	entries := []unified.IndexEntry{
		{Path: "osv/PyPI/PYSEC-2024-1.json", Kind: advisory.SourceOSV, Source: "PyPI", SourceID: "PYSEC-2024-1"},
		{Path: "cve/cvelistV5-main/cves/2024/0xxx/CVE-2024-0001.json", Kind: advisory.SourceCVE, SourceID: "CVE-2024-0001"},
	}

	rec, err := MergePrimary(context.Background(), root, "CVE-2024-0001", entries)
	if err != nil {
		t.Fatalf("MergePrimary: %v", err)
	}

	wantPub := time.Date(2024, 1, 15, 0, 0, 0, 0, time.UTC)
	wantMod := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)
	if !rec.Published.Equal(wantPub) {
		t.Errorf("Published = %v, want %v (earliest across sources)", rec.Published, wantPub)
	}
	if !rec.Modified.Equal(wantMod) {
		t.Errorf("Modified = %v, want %v (latest across sources)", rec.Modified, wantMod)
	}
}

// TestMergePrimary_DatesAbsentStayZero guards the omitzero contract:
// sources without dates must not fabricate one.
func TestMergePrimary_DatesAbsentStayZero(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "osv/PyPI/PYSEC-2024-2.json", `{"id":"PYSEC-2024-2"}`)
	entries := []unified.IndexEntry{
		{Path: "osv/PyPI/PYSEC-2024-2.json", Kind: advisory.SourceOSV, Source: "PyPI", SourceID: "PYSEC-2024-2"},
	}

	rec, err := MergePrimary(context.Background(), root, "PYSEC-2024-2", entries)
	if err != nil {
		t.Fatalf("MergePrimary: %v", err)
	}
	if !rec.Published.IsZero() || !rec.Modified.IsZero() {
		t.Errorf("dates = (%v, %v), want zero values", rec.Published, rec.Modified)
	}
}
