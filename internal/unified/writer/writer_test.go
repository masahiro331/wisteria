package writer_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/masahiro331/wisteria/internal/unified/writer"
	"github.com/masahiro331/wisteria/pkg/advisory"
)

func cveAdvisory(id, ecosystem string) advisory.UnifiedAdvisory {
	return advisory.UnifiedAdvisory{
		PrimaryID: id,
		Provenances: []advisory.Provenance{
			{Kind: advisory.SourceCVE, Path: "cve/x.json", ID: id},
		},
		// ecosystem only used by standalone bucket — kept here so the
		// helper has one signature.
		Descriptions: []advisory.Description{{Lang: "en", Text: ecosystem}},
	}
}

func standaloneAdvisory(id, ecosystem string) advisory.UnifiedAdvisory {
	return advisory.UnifiedAdvisory{
		PrimaryID: id,
		Provenances: []advisory.Provenance{
			{Kind: advisory.SourceOSV, Path: "osv/" + ecosystem + "/x.json", ID: id},
		},
	}
}

// initOutDir wraps writer.Init with the post-Init RemoveAll + MkdirAll
// dance that cmd/unify will do in production. Centralized in tests so
// the per-Write tests below can focus on bucket / escape / write logic.
func initOutDir(t *testing.T, cacheDir string) string {
	t.Helper()
	outDir, err := writer.Init(cacheDir)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := os.RemoveAll(outDir); err != nil {
		t.Fatalf("RemoveAll: %v", err)
	}
	if err := os.MkdirAll(outDir, 0o750); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	return outDir
}

func TestWrite_CVEBucketUsesYearFromID(t *testing.T) {
	cacheDir := t.TempDir()
	outDir := initOutDir(t, cacheDir)

	if err := writer.Write(outDir, cveAdvisory("CVE-2024-0001", "")); err != nil {
		t.Fatalf("Write: %v", err)
	}

	got := filepath.Join(cacheDir, "unified", "cve", "2024", "CVE-2024-0001.json")
	body, err := os.ReadFile(got)
	if err != nil {
		t.Fatalf("expected file %s: %v", got, err)
	}
	var round advisory.UnifiedAdvisory
	if err := json.Unmarshal(body, &round); err != nil {
		t.Fatalf("decode written file: %v", err)
	}
	if round.PrimaryID != "CVE-2024-0001" {
		t.Errorf("round-trip PrimaryID = %q", round.PrimaryID)
	}
}

func TestWrite_StandaloneBucketUsesPriorityProvenance(t *testing.T) {
	cacheDir := t.TempDir()
	outDir := initOutDir(t, cacheDir)

	if err := writer.Write(outDir, standaloneAdvisory("ALBA-2019:0973", "AlmaLinux")); err != nil {
		t.Fatalf("Write: %v", err)
	}

	want := filepath.Join(cacheDir, "unified", "standalone", "AlmaLinux", "ALBA-2019_0973.json")
	if _, err := os.Stat(want); err != nil {
		t.Fatalf("expected %s: %v", want, err)
	}
}

// TestWrite_StandaloneNormalizesEcosystemSpaces guards a subtle path
// drift: walker stores Source as "Red_Hat" (space → "_") but the OSV
// provenance Path keeps the on-disk "Red Hat". The writer derives the
// bucket from Path, so it must apply the same normalization before
// looking up priority — otherwise "osv.Red Hat" misses the priority
// table and Red Hat loses to a lower-priority OSV.
func TestWrite_StandaloneNormalizesEcosystemSpaces(t *testing.T) {
	cacheDir := t.TempDir()
	outDir := initOutDir(t, cacheDir)

	rec := advisory.UnifiedAdvisory{
		PrimaryID: "RHSA-2024-1",
		Provenances: []advisory.Provenance{
			// PyPI is unranked? — actually present in the priority list,
			// but lower than Red Hat. The test asserts Red_Hat wins.
			{Kind: advisory.SourceOSV, Path: "osv/PyPI/x.json", ID: "PYSEC-X"},
			{Kind: advisory.SourceOSV, Path: "osv/Red Hat/RHSA-2024-1.json", ID: "RHSA-2024-1"},
		},
	}
	if err := writer.Write(outDir, rec); err != nil {
		t.Fatalf("Write: %v", err)
	}
	want := filepath.Join(cacheDir, "unified", "standalone", "Red_Hat", "RHSA-2024-1.json")
	if _, err := os.Stat(want); err != nil {
		t.Errorf("expected %s, stat err = %v", want, err)
	}
}

func TestWrite_StandalonePicksHighestPriorityEcosystem(t *testing.T) {
	cacheDir := t.TempDir()
	outDir := initOutDir(t, cacheDir)

	rec := advisory.UnifiedAdvisory{
		PrimaryID: "OSV-PICK-1",
		Provenances: []advisory.Provenance{
			{Kind: advisory.SourceOSV, Path: "osv/PyPI/x.json", ID: "OSV-PICK-1"},
			{Kind: advisory.SourceOSV, Path: "osv/AlmaLinux/x.json", ID: "OSV-PICK-1"},
		},
	}
	if err := writer.Write(outDir, rec); err != nil {
		t.Fatalf("Write: %v", err)
	}
	want := filepath.Join(cacheDir, "unified", "standalone", "AlmaLinux", "OSV-PICK-1.json")
	if _, err := os.Stat(want); err != nil {
		t.Fatalf("expected %s: %v", want, err)
	}
}

func TestWrite_ConcurrentWritesShareBucketMkdir(t *testing.T) {
	// Many records into the same cve/2024/ bucket — Write must MkdirAll
	// the parent only once (or at least without errors when racing).
	cacheDir := t.TempDir()
	outDir := initOutDir(t, cacheDir)

	var wg sync.WaitGroup
	for i := range 50 {
		wg.Go(func() {
			id := fmt.Sprintf("CVE-2024-%04d", i)
			if err := writer.Write(outDir, cveAdvisory(id, "")); err != nil {
				t.Errorf("Write %s: %v", id, err)
			}
		})
	}
	wg.Wait()

	for i := range 50 {
		got := filepath.Join(cacheDir, "unified", "cve", "2024", fmt.Sprintf("CVE-2024-%04d.json", i))
		if _, err := os.Stat(got); err != nil {
			t.Errorf("missing %s: %v", got, err)
		}
	}
}

func TestInit_AcceptsRelativeCacheDir(t *testing.T) {
	tmp := t.TempDir()
	t.Chdir(tmp)

	outDir, err := writer.Init("rel")
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	if filepath.Base(outDir) != "unified" {
		t.Errorf("outDir basename = %q, want unified", filepath.Base(outDir))
	}
	// Init does not create the dir itself anymore — caller does.
	if _, err := os.Stat(outDir); !os.IsNotExist(err) {
		t.Errorf("Init should not create outDir, stat = %v", err)
	}
}

func TestInit_RejectsBadCacheDir(t *testing.T) {
	tests := []struct {
		name     string
		cacheDir string
	}{
		{name: "empty", cacheDir: ""},
		{name: "root", cacheDir: "/"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := writer.Init(tc.cacheDir)
			if err == nil {
				t.Fatal("expected guard error, got nil")
			}
		})
	}
}

func TestInit_RejectsUnifiedSymlink(t *testing.T) {
	cacheDir := t.TempDir()
	target := t.TempDir()
	link := filepath.Join(cacheDir, "unified")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	_, err := writer.Init(cacheDir)
	if err == nil {
		t.Fatal("expected error on unified symlink")
	}
}

func TestInit_RejectsUnifiedRegularFile(t *testing.T) {
	cacheDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(cacheDir, "unified"), []byte{}, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := writer.Init(cacheDir)
	if err == nil {
		t.Fatal("expected error on unified regular file")
	}
}

func TestWrite_FilenameEscapesUnsafeChars(t *testing.T) {
	cacheDir := t.TempDir()
	outDir := initOutDir(t, cacheDir)

	if err := writer.Write(outDir, standaloneAdvisory("ALBA-2019:0973", "AlmaLinux")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got := filepath.Join(cacheDir, "unified", "standalone", "AlmaLinux", "ALBA-2019_0973.json")
	if _, err := os.Stat(got); err != nil {
		t.Errorf("escaped filename missing: %v", err)
	}
}

func TestWrite_StandaloneWithoutOSVProvenanceErrors(t *testing.T) {
	cacheDir := t.TempDir()
	outDir := initOutDir(t, cacheDir)

	rec := advisory.UnifiedAdvisory{
		PrimaryID: "GHSA-aaaa-bbbb-cccc",
		Provenances: []advisory.Provenance{
			{Kind: advisory.SourceCVE, Path: "cve/x.json", ID: "GHSA-aaaa-bbbb-cccc"},
		},
	}
	if err := writer.Write(outDir, rec); err == nil {
		t.Fatal("expected error: standalone advisory needs an OSV provenance")
	}
}

// TestInit_ResetsBucketCacheAcrossRuns guards against a stale-cache bug:
// the package keeps a sync.Map of bucket dirs it has already MkdirAll'd
// to avoid 100k+ syscalls per run. If two runs reuse the same cacheDir
// in one process (tests, long-lived daemons), the second run's caller
// removes outDir, but a leftover cache hit would skip the MkdirAll and
// CreateTemp would then fail on a missing parent. Init must reset.
func TestInit_ResetsBucketCacheAcrossRuns(t *testing.T) {
	cacheDir := t.TempDir()

	for i := range 2 {
		outDir := initOutDir(t, cacheDir)
		if err := writer.Write(outDir, cveAdvisory("CVE-2024-0001", "")); err != nil {
			t.Fatalf("run %d Write: %v", i, err)
		}
	}
}

// keep context import live in case future tests need it
var _ = context.Background
