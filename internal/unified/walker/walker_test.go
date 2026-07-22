package walker_test

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/masahiro331/wisteria/internal/unified"
	"github.com/masahiro331/wisteria/internal/unified/walker"
	"github.com/masahiro331/wisteria/pkg/advisory"
)

// writeFile is a tiny test helper that creates parent dirs and writes
// `body` to <root>/<rel>. Tests only use it for OSV / CVE5 fixtures.
func writeFile(t *testing.T, root, rel, body string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestIndex(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		// PrimaryID -> set of IndexEntry signatures expected
		want map[string][]entryWant
	}{
		{
			name: "OSV with single CVE alias maps to CVE PrimaryID",
			files: map[string]string{
				"osv/PyPI/PYSEC-2024-1.json": `{"id":"PYSEC-2024-1","aliases":["CVE-2024-0001"]}`,
			},
			want: map[string][]entryWant{
				"CVE-2024-0001": {
					{kind: advisory.SourceOSV, source: "PyPI", sourceID: "PYSEC-2024-1", relPath: "osv/PyPI/PYSEC-2024-1.json"},
				},
			},
		},
		{
			name: "OSV with multi CVE aliases is duplicated under each CVE PrimaryID",
			files: map[string]string{
				"osv/PyPI/PYSEC-2024-2.json": `{"id":"PYSEC-2024-2","aliases":["CVE-2024-0002","CVE-2024-0003","GHSA-aaaa-bbbb-cccc"]}`,
			},
			want: map[string][]entryWant{
				"CVE-2024-0002": {
					{kind: advisory.SourceOSV, source: "PyPI", sourceID: "PYSEC-2024-2", relPath: "osv/PyPI/PYSEC-2024-2.json"},
				},
				"CVE-2024-0003": {
					{kind: advisory.SourceOSV, source: "PyPI", sourceID: "PYSEC-2024-2", relPath: "osv/PyPI/PYSEC-2024-2.json"},
				},
			},
		},
		{
			name: "OSV without CVE alias becomes standalone keyed by id",
			files: map[string]string{
				"osv/AlmaLinux/ALBA-2019:0973.json": `{"id":"ALBA-2019:0973","aliases":["RHSA-2019:0973"]}`,
				"osv/Go/GO-2024-1234.json":          `{"id":"GO-2024-1234"}`,
			},
			want: map[string][]entryWant{
				"ALBA-2019:0973": {
					{kind: advisory.SourceOSV, source: "AlmaLinux", sourceID: "ALBA-2019:0973", relPath: "osv/AlmaLinux/ALBA-2019:0973.json"},
				},
				"GO-2024-1234": {
					{kind: advisory.SourceOSV, source: "Go", sourceID: "GO-2024-1234", relPath: "osv/Go/GO-2024-1234.json"},
				},
			},
		},
		{
			name: "CVE5 entries are keyed by filename CVE-ID without reading body",
			files: map[string]string{
				"cve/cvelistV5-main/cves/2024/0xxx/CVE-2024-0001.json": "not-even-json-on-purpose",
			},
			want: map[string][]entryWant{
				"CVE-2024-0001": {
					{kind: advisory.SourceCVE, source: "", sourceID: "CVE-2024-0001", relPath: "cve/cvelistV5-main/cves/2024/0xxx/CVE-2024-0001.json"},
				},
			},
		},
		{
			name: "OSV CVE alias and CVE5 file converge on same PrimaryID with both entries",
			files: map[string]string{
				"osv/PyPI/PYSEC-2024-9.json":                           `{"id":"PYSEC-2024-9","aliases":["CVE-2024-9999"]}`,
				"cve/cvelistV5-main/cves/2024/9xxx/CVE-2024-9999.json": "{}",
			},
			want: map[string][]entryWant{
				"CVE-2024-9999": {
					{kind: advisory.SourceOSV, source: "PyPI", sourceID: "PYSEC-2024-9", relPath: "osv/PyPI/PYSEC-2024-9.json"},
					{kind: advisory.SourceCVE, source: "", sourceID: "CVE-2024-9999", relPath: "cve/cvelistV5-main/cves/2024/9xxx/CVE-2024-9999.json"},
				},
			},
		},
		{
			name: "OSV ecosystem with spaces is normalized (space -> _) in Source",
			files: map[string]string{
				"osv/Rocky Linux/RLSA-2024-1.json": `{"id":"RLSA-2024-1"}`,
			},
			want: map[string][]entryWant{
				"RLSA-2024-1": {
					{kind: advisory.SourceOSV, source: "Rocky_Linux", sourceID: "RLSA-2024-1", relPath: "osv/Rocky Linux/RLSA-2024-1.json"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			for rel, body := range tt.files {
				writeFile(t, root, rel, body)
			}

			got, err := walker.Index(context.Background(), root)
			if err != nil {
				t.Fatalf("Index: %v", err)
			}

			if len(got) != len(tt.want) {
				t.Fatalf("PrimaryID count: got %d (%v), want %d", len(got), keys(got), len(tt.want))
			}

			for pid, wantEntries := range tt.want {
				gotEntries, ok := got[pid]
				if !ok {
					t.Errorf("PrimaryID %q: missing from result", pid)
					continue
				}
				if len(gotEntries) != len(wantEntries) {
					t.Errorf("PrimaryID %q: got %d entries, want %d", pid, len(gotEntries), len(wantEntries))
					continue
				}
				gotSig := signatures(gotEntries)
				wantSig := wantSignatures(wantEntries)
				sort.Strings(gotSig)
				sort.Strings(wantSig)
				for i := range gotSig {
					if gotSig[i] != wantSig[i] {
						t.Errorf("PrimaryID %q entry %d: got %q, want %q", pid, i, gotSig[i], wantSig[i])
					}
				}
				// Path is relative to sourcesRoot; joining must yield a
				// real file. This catches both absolute-path leaks and
				// missing-file regressions in one check.
				for _, e := range gotEntries {
					if filepath.IsAbs(e.Path) {
						t.Errorf("PrimaryID %q: Path %q must be relative to sourcesRoot", pid, e.Path)
					}
					if _, err := os.Stat(filepath.Join(root, e.Path)); err != nil {
						t.Errorf("PrimaryID %q: joined path does not exist: %v", pid, err)
					}
				}
			}
		})
	}
}

func TestIndex_MalformedOSVAborts(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "osv/PyPI/broken.json", "{this is not json")

	_, err := walker.Index(context.Background(), root)
	if err == nil {
		t.Fatal("Index: expected error for malformed OSV file, got nil")
	}
}

func TestIndex_MissingSourcesRootIsError(t *testing.T) {
	_, err := walker.Index(context.Background(), filepath.Join(t.TempDir(), "does-not-exist"))
	if err == nil {
		t.Fatal("Index: expected error for missing root, got nil")
	}
}

func TestIndex_EmptyRootReturnsEmptyMap(t *testing.T) {
	root := t.TempDir()
	got, err := walker.Index(context.Background(), root)
	if err != nil {
		t.Fatalf("Index: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("Index: got %d PrimaryIDs, want 0", len(got))
	}
}

func TestIndex_NonJSONFilesUnderOSVAreIgnored(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "osv/PyPI/README.md", "not json")
	writeFile(t, root, "osv/PyPI/PYSEC-2024-1.json", `{"id":"PYSEC-2024-1"}`)

	got, err := walker.Index(context.Background(), root)
	if err != nil {
		t.Fatalf("Index: %v", err)
	}
	if _, ok := got["PYSEC-2024-1"]; !ok {
		t.Fatalf("Index: missing PYSEC-2024-1")
	}
	if len(got) != 1 {
		t.Fatalf("Index: got %d PrimaryIDs, want 1", len(got))
	}
}

func TestIndex_RelativeSourcesRootKeepsRelativePaths(t *testing.T) {
	// Path must always be relative to sourcesRoot, even when sourcesRoot
	// itself is given as a relative path. This is the regression test for
	// the original AbsPath/RelPath split (which leaked the caller's CWD
	// into AbsPath when sourcesRoot was relative).
	abs := t.TempDir()
	writeFile(t, abs, "osv/PyPI/PYSEC-2024-1.json", `{"id":"PYSEC-2024-1"}`)

	t.Chdir(filepath.Dir(abs))

	got, err := walker.Index(context.Background(), filepath.Base(abs))
	if err != nil {
		t.Fatalf("Index: %v", err)
	}
	entries := got["PYSEC-2024-1"]
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	if filepath.IsAbs(entries[0].Path) {
		t.Errorf("Path %q must be relative", entries[0].Path)
	}
	if entries[0].Path != filepath.Join("osv", "PyPI", "PYSEC-2024-1.json") {
		t.Errorf("Path = %q, want osv/PyPI/PYSEC-2024-1.json", entries[0].Path)
	}
}

func TestIndex_CVESymlinkIsIgnored(t *testing.T) {
	// A symlink named like CVE-*.json must not be indexed: Stage 2
	// reopens IndexEntry.Path via filepath.Join, so following such a
	// link could read outside sourcesRoot. The OSV side already guards
	// against this; the CVE side must mirror it.
	root := t.TempDir()
	writeFile(t, root, "cve/cvelistV5-main/cves/2024/0xxx/CVE-2024-0001.json", "{}")

	outside := filepath.Join(root, "outside-secret.json")
	if err := os.WriteFile(outside, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "cve", "cvelistV5-main", "cves", "2024", "9xxx", "CVE-2024-9999.json")
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}

	got, err := walker.Index(context.Background(), root)
	if err != nil {
		t.Fatalf("Index: %v", err)
	}
	if _, ok := got["CVE-2024-9999"]; ok {
		t.Errorf("Index: symlink CVE-2024-9999 must not be indexed")
	}
	if got["CVE-2024-0001"] == nil {
		t.Errorf("Index: real CVE-2024-0001 missing")
	}
}

func TestIndex_CVEOutsideCvesSubtreeIsIgnored(t *testing.T) {
	// upstream cvelistV5 ships test fixtures and helper scripts that may
	// include CVE-*.json files outside cvelistV5-main/cves/. Only the
	// catalog subtree is the real advisory source — anything else must
	// not pollute the index.
	root := t.TempDir()
	writeFile(t, root, "cve/cvelistV5-main/cves/2024/0xxx/CVE-2024-0001.json", "{}")
	writeFile(t, root, "cve/cvelistV5-main/tests/fixtures/CVE-9999-0001.json", "{}")
	writeFile(t, root, "cve/cvelistV5-main/CVE-9999-0002.json", "{}")

	got, err := walker.Index(context.Background(), root)
	if err != nil {
		t.Fatalf("Index: %v", err)
	}
	if len(got) != 1 || got["CVE-2024-0001"] == nil {
		t.Fatalf("Index: got %v, want only CVE-2024-0001", keys(got))
	}
}

func TestIndex_CVEFilenameWithoutCVEPrefixIsIgnored(t *testing.T) {
	// delta.json, deltaLog.json etc. live alongside CVE-*.json under the
	// upstream cvelistV5 repo; they are not advisory records and must not
	// appear in the index.
	root := t.TempDir()
	writeFile(t, root, "cve/cvelistV5-main/cves/2024/0xxx/CVE-2024-0001.json", "{}")
	writeFile(t, root, "cve/cvelistV5-main/cves/delta.json", "{}")
	writeFile(t, root, "cve/cvelistV5-main/README.md", "")

	got, err := walker.Index(context.Background(), root)
	if err != nil {
		t.Fatalf("Index: %v", err)
	}
	if len(got) != 1 || got["CVE-2024-0001"] == nil {
		t.Fatalf("Index: got %v, want only CVE-2024-0001", keys(got))
	}
}

// ---- helpers ----

func keys(m map[string][]unified.IndexEntry) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func signatures(entries []unified.IndexEntry) []string {
	out := make([]string, len(entries))
	for i, e := range entries {
		out[i] = string(e.Kind) + "|" + e.Source + "|" + e.SourceID + "|" + e.Path
	}
	return out
}

type entryWant struct {
	kind     advisory.SourceKind
	source   string
	sourceID string
	relPath  string
}

func wantSignatures(entries []entryWant) []string {
	out := make([]string, len(entries))
	for i, e := range entries {
		out[i] = string(e.kind) + "|" + e.source + "|" + e.sourceID + "|" + e.relPath
	}
	return out
}

// TestIndex_SkipsUnreadableOSVFileWithWarning covers endpoint-protection
// quarantine: Microsoft Defender strips read permission from (or removes)
// advisories that embed malicious PoC content (MAL-* records). One
// quarantined file must not abort the whole walk — it is warned about
// and left out of the index.
func TestIndex_SkipsUnreadableOSVFileWithWarning(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "osv/PyPI/PYSEC-2024-1.json", `{"id":"PYSEC-2024-1"}`)
	writeFile(t, root, "osv/PyPI/MAL-2026-1262.json", `{"id":"MAL-2026-1262"}`)
	quarantined := filepath.Join(root, "osv", "PyPI", "MAL-2026-1262.json")
	if err := os.Chmod(quarantined, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(quarantined, 0o644) })

	var warns strings.Builder
	got, err := walker.Index(context.Background(), root, walker.WithWarnLog(&warns))
	if err != nil {
		t.Fatalf("Index: %v", err)
	}
	if _, ok := got["MAL-2026-1262"]; ok {
		t.Error("quarantined file must not enter the index")
	}
	if _, ok := got["PYSEC-2024-1"]; !ok {
		t.Error("readable sibling must still be indexed")
	}
	if !strings.Contains(warns.String(), "MAL-2026-1262.json") {
		t.Errorf("warning must name the skipped file; got %q", warns.String())
	}
}

// TestIndex_NilWarnLogStillSkips guards the default: no warn writer
// configured means silent skip, not a nil-deref or an abort.
func TestIndex_NilWarnLogStillSkips(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "osv/PyPI/MAL-2026-1262.json", `{"id":"MAL-2026-1262"}`)
	quarantined := filepath.Join(root, "osv", "PyPI", "MAL-2026-1262.json")
	if err := os.Chmod(quarantined, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(quarantined, 0o644) })

	got, err := walker.Index(context.Background(), root)
	if err != nil {
		t.Fatalf("Index: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("index = %v, want empty", got)
	}
}

// TestIndex_MalformedJSONStillAborts pins the boundary of the skip
// policy: only inaccessible files (quarantine / vanish) are skipped;
// data corruption keeps failing loud.
func TestIndex_MalformedJSONStillAborts(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "osv/PyPI/bad.json", `{not json`)

	if _, err := walker.Index(context.Background(), root); err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}
