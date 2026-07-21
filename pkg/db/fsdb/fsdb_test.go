package fsdb_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/masahiro331/wisteria/internal/unified/indexer"
	"github.com/masahiro331/wisteria/internal/unified/writer"
	"github.com/masahiro331/wisteria/pkg/advisory"
	"github.com/masahiro331/wisteria/pkg/advisory/osv"
	"github.com/masahiro331/wisteria/pkg/db"
	"github.com/masahiro331/wisteria/pkg/db/fsdb"
)

func fixtureRecords() []advisory.UnifiedAdvisory {
	return []advisory.UnifiedAdvisory{
		{
			PrimaryID: "CVE-2024-0001",
			SourceIDs: []string{"GHSA-shared-alias", "PYSEC-2024-1"},
			Provenances: []advisory.Provenance{
				{Kind: advisory.SourceCVE, Path: "cve/x.json", ID: "CVE-2024-0001"},
			},
			Affected: []advisory.AffectedRecord{{
				From: advisory.Provenance{Kind: advisory.SourceOSV, Path: "osv/PyPI/x.json", ID: "PYSEC-2024-1"},
				OSV:  &osv.Affected{Package: osv.Package{Ecosystem: "PyPI", Name: "django"}},
			}},
		},
		{
			PrimaryID: "CVE-2024-0002",
			SourceIDs: []string{"GHSA-shared-alias"},
			Provenances: []advisory.Provenance{
				{Kind: advisory.SourceCVE, Path: "cve/y.json", ID: "CVE-2024-0002"},
			},
		},
		{
			PrimaryID: "GO-2024-1234",
			Provenances: []advisory.Provenance{
				{Kind: advisory.SourceOSV, Path: "osv/Go/GO-2024-1234.json", ID: "GO-2024-1234"},
			},
			Affected: []advisory.AffectedRecord{{
				From: advisory.Provenance{Kind: advisory.SourceOSV, Path: "osv/Go/GO-2024-1234.json", ID: "GO-2024-1234"},
				OSV:  &osv.Affected{Package: osv.Package{Ecosystem: "Go", Name: "github.com/foo/bar"}},
			}},
		},
	}
}

// buildTree writes the fixture records (and, unless withIndex is false,
// the Stage 5 index) into a fresh unified tree and returns its path.
func buildTree(t *testing.T, withIndex bool) string {
	t.Helper()
	cacheDir := t.TempDir()
	outDir, err := writer.Reset(cacheDir)
	if err != nil {
		t.Fatalf("writer.Reset: %v", err)
	}
	ix := indexer.New()
	for _, rec := range fixtureRecords() {
		if err := writer.Write(outDir, rec); err != nil {
			t.Fatalf("writer.Write %s: %v", rec.PrimaryID, err)
		}
		if err := ix.Collect(rec); err != nil {
			t.Fatalf("indexer.Collect %s: %v", rec.PrimaryID, err)
		}
	}
	if withIndex {
		if err := ix.Write(outDir); err != nil {
			t.Fatalf("indexer.Write: %v", err)
		}
	}
	return outDir
}

func openDriver(t *testing.T, outDir string) *fsdb.Driver {
	t.Helper()
	d, err := fsdb.Open(outDir)
	if err != nil {
		t.Fatalf("fsdb.Open: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d
}

func TestFind_PrimaryID(t *testing.T) {
	d := openDriver(t, buildTree(t, true))

	got, err := d.Find(context.Background(), "CVE-2024-0001")
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if len(got) != 1 || got[0].PrimaryID != "CVE-2024-0001" {
		t.Errorf("Find = %d records (%+v), want 1 × CVE-2024-0001", len(got), got)
	}
}

func TestFind_StandalonePrimaryID(t *testing.T) {
	d := openDriver(t, buildTree(t, true))

	got, err := d.Find(context.Background(), "GO-2024-1234")
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if len(got) != 1 || got[0].PrimaryID != "GO-2024-1234" {
		t.Errorf("Find = %+v, want GO-2024-1234", got)
	}
}

func TestFind_AliasResolvesToMultipleOrderedByPrimaryID(t *testing.T) {
	d := openDriver(t, buildTree(t, true))

	got, err := d.Find(context.Background(), "GHSA-shared-alias")
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if len(got) != 2 || got[0].PrimaryID != "CVE-2024-0001" || got[1].PrimaryID != "CVE-2024-0002" {
		ids := make([]string, len(got))
		for i, r := range got {
			ids[i] = r.PrimaryID
		}
		t.Errorf("Find(alias) = %v, want [CVE-2024-0001 CVE-2024-0002]", ids)
	}
}

func TestFind_UnknownIDIsNotFound(t *testing.T) {
	d := openDriver(t, buildTree(t, true))

	_, err := d.Find(context.Background(), "CVE-1999-9999")
	if !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestFindByPackage_Hit(t *testing.T) {
	d := openDriver(t, buildTree(t, true))

	got, err := d.FindByPackage(context.Background(), "PyPI", "django")
	if err != nil {
		t.Fatalf("FindByPackage: %v", err)
	}
	if len(got) != 1 || got[0].PrimaryID != "CVE-2024-0001" {
		t.Errorf("FindByPackage = %+v, want CVE-2024-0001", got)
	}
}

func TestFindByPackage_SlashInName(t *testing.T) {
	d := openDriver(t, buildTree(t, true))

	got, err := d.FindByPackage(context.Background(), "Go", "github.com/foo/bar")
	if err != nil {
		t.Fatalf("FindByPackage: %v", err)
	}
	if len(got) != 1 || got[0].PrimaryID != "GO-2024-1234" {
		t.Errorf("FindByPackage = %+v, want GO-2024-1234", got)
	}
}

func TestFindByPackage_MissIsEmptyNotError(t *testing.T) {
	d := openDriver(t, buildTree(t, true))

	got, err := d.FindByPackage(context.Background(), "PyPI", "no-such-package")
	if err != nil {
		t.Fatalf("FindByPackage: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("FindByPackage = %+v, want empty", got)
	}
}

func TestIndexlessTree_CVEDirectPathFallback(t *testing.T) {
	d := openDriver(t, buildTree(t, false))

	got, err := d.Find(context.Background(), "CVE-2024-0001")
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if len(got) != 1 || got[0].PrimaryID != "CVE-2024-0001" {
		t.Errorf("Find = %+v, want CVE-2024-0001", got)
	}

	// A CVE-shaped id that has no record is still a plain not-found.
	if _, err := d.Find(context.Background(), "CVE-1999-9999"); !errors.Is(err, db.ErrNotFound) {
		t.Errorf("missing CVE err = %v, want ErrNotFound", err)
	}
}

func TestIndexlessTree_NonCVEAndPackageLookupsError(t *testing.T) {
	d := openDriver(t, buildTree(t, false))

	if _, err := d.Find(context.Background(), "GHSA-shared-alias"); err == nil || errors.Is(err, db.ErrNotFound) {
		t.Errorf("Find(alias) on index-less tree: err = %v, want explicit no-index error", err)
	}
	if _, err := d.FindByPackage(context.Background(), "PyPI", "django"); err == nil {
		t.Error("FindByPackage on index-less tree: want explicit no-index error")
	}
}

func TestUnsupportedIndexVersionErrors(t *testing.T) {
	outDir := buildTree(t, true)
	meta := filepath.Join(outDir, "index", "meta.json")
	if err := os.WriteFile(meta, []byte(`{"version":99}`), 0o644); err != nil {
		t.Fatal(err)
	}
	d := openDriver(t, outDir)

	if _, err := d.Find(context.Background(), "CVE-2024-0001"); err == nil {
		t.Fatal("expected error for unsupported index version")
	}
}

func TestOpen_RejectsMissingOrNonDirectory(t *testing.T) {
	if _, err := fsdb.Open(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Error("expected error for missing directory")
	}
	f := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(f, []byte{}, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := fsdb.Open(f); err == nil {
		t.Error("expected error for non-directory")
	}
}

func TestDSN_OpenViaRegistry(t *testing.T) {
	outDir := buildTree(t, true)

	d, err := db.Open(context.Background(), "fs://"+outDir)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })

	got, err := d.Find(context.Background(), "CVE-2024-0001")
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("Find = %d records, want 1", len(got))
	}
}

func TestDSN_RejectsHostAndOpaqueForms(t *testing.T) {
	for _, dsn := range []string{"fs://host/path", "fs:relative/path", "fs://"} {
		if _, err := db.Open(context.Background(), dsn); err == nil {
			t.Errorf("db.Open(%q): expected error", dsn)
		}
	}
}
