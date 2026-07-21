package indexer_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/masahiro331/wisteria/internal/unified/indexer"
	"github.com/masahiro331/wisteria/pkg/advisory"
	"github.com/masahiro331/wisteria/pkg/advisory/osv"
)

func cveRec(primaryID string, sourceIDs []string, pkgs ...osv.Package) advisory.UnifiedAdvisory {
	rec := advisory.UnifiedAdvisory{
		PrimaryID: primaryID,
		SourceIDs: sourceIDs,
		Provenances: []advisory.Provenance{
			{Kind: advisory.SourceCVE, Path: "cve/x.json", ID: primaryID},
		},
	}
	for _, p := range pkgs {
		rec.Affected = append(rec.Affected, advisory.AffectedRecord{
			From: advisory.Provenance{Kind: advisory.SourceOSV, Path: "osv/" + p.Ecosystem + "/x.json", ID: primaryID},
			OSV:  &osv.Affected{Package: p},
		})
	}
	return rec
}

func readEntry(t *testing.T, path string) indexer.Entry {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var e indexer.Entry
	if err := json.Unmarshal(body, &e); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return e
}

func TestWrite_MetaVersion(t *testing.T) {
	outDir := t.TempDir()
	ix := indexer.New()
	if err := ix.Write(outDir); err != nil {
		t.Fatalf("Write: %v", err)
	}
	body, err := os.ReadFile(filepath.Join(outDir, "index", "meta.json"))
	if err != nil {
		t.Fatalf("meta.json: %v", err)
	}
	var meta indexer.Meta
	if err := json.Unmarshal(body, &meta); err != nil {
		t.Fatalf("decode meta.json: %v", err)
	}
	if meta.Version != indexer.MetaVersion {
		t.Errorf("meta version = %d, want %d", meta.Version, indexer.MetaVersion)
	}
}

func TestCollectWrite_IDEntriesCoverPrimaryAndAliases(t *testing.T) {
	outDir := t.TempDir()
	ix := indexer.New()
	if err := ix.Collect(cveRec("CVE-2021-42343", []string{"GHSA-hwqr-aaaa-bbbb", "PYSEC-2021-872"})); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if err := ix.Write(outDir); err != nil {
		t.Fatalf("Write: %v", err)
	}

	for _, id := range []string{"CVE-2021-42343", "GHSA-hwqr-aaaa-bbbb", "PYSEC-2021-872"} {
		got := readEntry(t, filepath.Join(outDir, "index", "ids", id+".json"))
		want := indexer.Entry{Records: []indexer.RecordRef{
			{PrimaryID: "CVE-2021-42343", Path: "cve/2021/CVE-2021-42343.json"},
		}}
		if len(got.Records) != 1 || got.Records[0] != want.Records[0] {
			t.Errorf("ids/%s = %+v, want %+v", id, got, want)
		}
	}
}

func TestCollectWrite_SharedAliasSortsRecordsByPrimaryID(t *testing.T) {
	outDir := t.TempDir()
	ix := indexer.New()
	// Collect in reverse order to prove the output is sorted, not
	// insertion-ordered.
	if err := ix.Collect(cveRec("CVE-2024-0002", []string{"GHSA-hwqr-aaaa-bbbb"})); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if err := ix.Collect(cveRec("CVE-2024-0001", []string{"GHSA-hwqr-aaaa-bbbb"})); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if err := ix.Write(outDir); err != nil {
		t.Fatalf("Write: %v", err)
	}

	got := readEntry(t, filepath.Join(outDir, "index", "ids", "GHSA-hwqr-aaaa-bbbb.json"))
	if len(got.Records) != 2 ||
		got.Records[0].PrimaryID != "CVE-2024-0001" ||
		got.Records[1].PrimaryID != "CVE-2024-0002" {
		t.Errorf("shared alias records = %+v, want CVE-2024-0001 then CVE-2024-0002", got.Records)
	}
}

func TestCollectWrite_PackageEntriesEscapeSegments(t *testing.T) {
	outDir := t.TempDir()
	ix := indexer.New()
	rec := cveRec("CVE-2024-0001", nil,
		osv.Package{Ecosystem: "PyPI", Name: "django"},
		osv.Package{Ecosystem: "Go", Name: "github.com/foo/bar"},
	)
	if err := ix.Collect(rec); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if err := ix.Write(outDir); err != nil {
		t.Fatalf("Write: %v", err)
	}

	plain := readEntry(t, filepath.Join(outDir, "index", "packages", "PyPI", "django.json"))
	if len(plain.Records) != 1 || plain.Records[0].PrimaryID != "CVE-2024-0001" {
		t.Errorf("packages/PyPI/django = %+v", plain.Records)
	}
	// "/" in a package name must be escaped so one package = one file.
	escaped := readEntry(t, filepath.Join(outDir, "index", "packages", "Go", "github.com%2Ffoo%2Fbar.json"))
	if len(escaped.Records) != 1 || escaped.Records[0].PrimaryID != "CVE-2024-0001" {
		t.Errorf("packages/Go/github.com%%2Ffoo%%2Fbar = %+v", escaped.Records)
	}
}

func TestCollect_SkipsEmptyPackageFields(t *testing.T) {
	outDir := t.TempDir()
	ix := indexer.New()
	rec := cveRec("CVE-2024-0001", nil,
		osv.Package{Ecosystem: "", Name: "orphan"},
		osv.Package{Ecosystem: "PyPI", Name: ""},
	)
	if err := ix.Collect(rec); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if err := ix.Write(outDir); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outDir, "index", "packages")); !os.IsNotExist(err) {
		t.Errorf("packages dir should not exist for empty ecosystem/name, stat err = %v", err)
	}
}

func TestWrite_RebuildsIndexFromScratch(t *testing.T) {
	outDir := t.TempDir()
	stale := filepath.Join(outDir, "index", "ids", "STALE-1.json")
	if err := os.MkdirAll(filepath.Dir(stale), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stale, []byte(`{"records":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}

	ix := indexer.New()
	if err := ix.Collect(cveRec("CVE-2024-0001", nil)); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if err := ix.Write(outDir); err != nil {
		t.Fatalf("Write: %v", err)
	}

	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Errorf("stale index entry survived rebuild, stat err = %v", err)
	}
	if _, err := os.Stat(filepath.Join(outDir, "index", "ids", "CVE-2024-0001.json")); err != nil {
		t.Errorf("fresh entry missing: %v", err)
	}
}

func TestCollect_StandaloneWithoutOSVProvenanceErrors(t *testing.T) {
	ix := indexer.New()
	rec := advisory.UnifiedAdvisory{
		PrimaryID: "GHSA-aaaa-bbbb-cccc",
		Provenances: []advisory.Provenance{
			{Kind: advisory.SourceCVE, Path: "cve/x.json", ID: "GHSA-aaaa-bbbb-cccc"},
		},
	}
	if err := ix.Collect(rec); err == nil {
		t.Fatal("expected error: standalone advisory needs an OSV provenance for routing")
	}
}

func TestPathHelpers(t *testing.T) {
	if got, want := indexer.MetaPath(), "index/meta.json"; got != want {
		t.Errorf("MetaPath = %q, want %q", got, want)
	}
	if got, want := indexer.IDPath("ALBA-2019:0973"), "index/ids/ALBA-2019:0973.json"; got != want {
		t.Errorf("IDPath = %q, want %q", got, want)
	}
	if got, want := indexer.PackagePath("Go", "github.com/foo/bar"), "index/packages/Go/github.com%2Ffoo%2Fbar.json"; got != want {
		t.Errorf("PackagePath = %q, want %q", got, want)
	}
}
