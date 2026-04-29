package debug_test

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/masahiro331/wisteria/cmd"
	"github.com/masahiro331/wisteria/internal/unified"
)

// unifyFixtureCacheDir builds a sources tree where one CVE has both an
// OSV alias and a CVE5 record (with a CISA ADP container) so the JSON
// output exercises every merge function: References (URL dedup + tag
// union), Descriptions (parallel hold for OSV Summary+Details and
// CNA+ADP), Severities (priority-based dedup), Affected (parallel hold
// across sources, OSV/CVE substructure preserved).
func unifyFixtureCacheDir(t *testing.T) string {
	t.Helper()
	cacheDir := t.TempDir()
	src := filepath.Join(cacheDir, "sources")
	writeFile(t, src, "osv/AlmaLinux/ALSA-1.json", `{
		"id": "ALSA-1",
		"aliases": ["CVE-2024-0001"],
		"summary": "OSV summary line",
		"details": "OSV detailed body.",
		"references": [
			{"type": "ADVISORY", "url": "https://example.com/a/"}
		],
		"severity": [
			{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N"}
		],
		"affected": [
			{"package": {"name": "pkgA", "ecosystem": "AlmaLinux"}}
		]
	}`)
	writeFile(t, src, "cve/cvelistV5-main/cves/2024/0xxx/CVE-2024-0001.json", `{
		"cveMetadata": {"cveId": "CVE-2024-0001"},
		"containers": {
			"cna": {
				"descriptions": [
					{"lang": "en", "value": "CNA description"}
				],
				"references": [
					{"url": "HTTPS://Example.COM/a", "tags": ["vendor-advisory"]},
					{"url": "https://nvd.example/cve-2024-0001"}
				],
				"metrics": [
					{"cvssV3_1": {"vectorString": "CVSS:3.1/AV:N", "baseScore": 9.8}}
				],
				"affected": [
					{"vendor": "acme", "product": "widget"}
				]
			},
			"adp": [
				{
					"providerMetadata": {"shortName": "CISA-ADP"},
					"descriptions": [
						{"lang": "en", "value": "ADP enrichment description"}
					],
					"affected": [
						{"vendor": "acme", "product": "widget-adp"}
					]
				}
			]
		}
	}`)
	return cacheDir
}

func runDebugUnify(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	root := cmd.NewRootCmd()
	full := append([]string{"debug", "unify"}, args...)
	root.SetArgs(full)
	var out, errBuf bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errBuf)
	err = root.ExecuteContext(context.Background())
	return out.String(), errBuf.String(), err
}

// runUnifyAndDecode is the shared setup: build the fixture, invoke
// `wisteria debug unify --id <id>`, parse the stdout JSON. Tests below
// assert one merge concern each so failures point at the broken field.
func runUnifyAndDecode(t *testing.T) unified.UnifiedAdvisory {
	t.Helper()
	cacheDir := unifyFixtureCacheDir(t)
	stdout, _, err := runDebugUnify(t, "--cache-dir", cacheDir, "--id", "CVE-2024-0001")
	if err != nil {
		t.Fatalf("debug unify: %v", err)
	}
	var got unified.UnifiedAdvisory
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("decode JSON: %v\nstdout:\n%s", err, stdout)
	}
	if got.PrimaryID != "CVE-2024-0001" {
		t.Fatalf("PrimaryID = %q, want CVE-2024-0001", got.PrimaryID)
	}
	return got
}

func TestDebugUnify_References(t *testing.T) {
	got := runUnifyAndDecode(t)
	// 2 unique URLs after normalization: OSV "/a/" and CVE
	// "HTTPS://Example.COM/a" collapse; "https://nvd.example/..." is
	// the second entry.
	if len(got.References) != 2 {
		t.Fatalf("References len = %d, want 2: %#v", len(got.References), got.References)
	}
	if got.References[0].URL != "https://example.com/a" {
		t.Errorf("References[0].URL = %q", got.References[0].URL)
	}
	gotTags := got.References[0].Tags
	if len(gotTags) != 2 || gotTags[0] != "ADVISORY" || gotTags[1] != "vendor-advisory" {
		t.Errorf("References[0].Tags = %v, want [ADVISORY vendor-advisory]", gotTags)
	}
}

func TestDebugUnify_Severities(t *testing.T) {
	got := runUnifyAndDecode(t)
	// Same Type+Vector across OSV and CVE collapses to 1; cve.mitre
	// outranks osv.AlmaLinux so its Provenance wins.
	if len(got.Severities) != 1 {
		t.Fatalf("Severities len = %d, want 1: %#v", len(got.Severities), got.Severities)
	}
	if got.Severities[0].From.Kind != unified.SourceCVE {
		t.Errorf("Severities[0].From.Kind = %q, want cve", got.Severities[0].From.Kind)
	}
}

func TestDebugUnify_Descriptions(t *testing.T) {
	got := runUnifyAndDecode(t)
	// CNA (rank 0) → ADP (rank 0, later by ID suffix) → OSV summary
	// (rank 2, lang en, index 0) → OSV details (rank 2, lang en, index 1).
	want := []string{
		"CNA description",
		"ADP enrichment description",
		"OSV summary line",
		"OSV detailed body.",
	}
	if len(got.Descriptions) != len(want) {
		t.Fatalf("Descriptions len = %d, want %d: %#v", len(got.Descriptions), len(want), got.Descriptions)
	}
	for i, w := range want {
		if got.Descriptions[i].Text != w {
			t.Errorf("Descriptions[%d].Text = %q, want %q", i, got.Descriptions[i].Text, w)
		}
	}
}

func TestDebugUnify_Affected(t *testing.T) {
	got := runUnifyAndDecode(t)
	// 3 entries (CNA widget + ADP widget-adp + OSV pkgA) — parallel
	// hold; substructure preserved per source.
	if len(got.Affected) != 3 {
		t.Fatalf("Affected len = %d, want 3: %#v", len(got.Affected), got.Affected)
	}
	if got.Affected[0].CVE == nil || got.Affected[0].CVE.Product != "widget" {
		t.Errorf("Affected[0] CVE = %#v", got.Affected[0].CVE)
	}
	if got.Affected[1].CVE == nil || got.Affected[1].CVE.Product != "widget-adp" {
		t.Errorf("Affected[1] CVE = %#v", got.Affected[1].CVE)
	}
	// got.Affected[2].OSV decodes back to a generic map because the
	// JSON pipeline went OSV-AffectedX → marshal → unmarshal-into-any
	// in this test. Check the package name via the map.
	osvAff, _ := got.Affected[2].OSV.(map[string]any)
	if osvAff == nil {
		t.Fatalf("Affected[2] OSV is nil/wrong type: %#v", got.Affected[2].OSV)
	}
	pkg, _ := osvAff["package"].(map[string]any)
	if pkg == nil || pkg["name"] != "pkgA" {
		t.Errorf("Affected[2] OSV package = %#v", osvAff["package"])
	}
}

func TestDebugUnify_Provenances(t *testing.T) {
	got := runUnifyAndDecode(t)
	// OSV (1) + CVE CNA (1) + CVE ADP (1) = 3.
	if len(got.Provenances) != 3 {
		t.Errorf("Provenances len = %d, want 3", len(got.Provenances))
	}
}

func TestDebugUnify_RequiresID(t *testing.T) {
	cacheDir := unifyFixtureCacheDir(t)
	_, _, err := runDebugUnify(t, "--cache-dir", cacheDir)
	if err == nil {
		t.Fatal("expected error when neither --id nor --sample is given")
	}
}

func TestDebugUnify_IDNotFound(t *testing.T) {
	cacheDir := unifyFixtureCacheDir(t)
	_, _, err := runDebugUnify(t, "--cache-dir", cacheDir, "--id", "CVE-9999-9999")
	if err == nil {
		t.Fatal("expected error for unknown PrimaryID")
	}
}

// sampleFixture lays out three OSV records with different PrimaryIDs so
// --sample has something to pick from. Lex-sorted order is
// CVE-2024-0001 → CVE-2024-0002 → GO-2024-9000, so --sample 2 must
// emit the two CVE entries (deterministically) and skip the Go one.
func sampleFixture(t *testing.T) string {
	t.Helper()
	cacheDir := t.TempDir()
	src := filepath.Join(cacheDir, "sources")
	writeFile(t, src, "osv/PyPI/PYSEC-1.json",
		`{"id":"PYSEC-1","aliases":["CVE-2024-0001"],"summary":"py 1"}`)
	writeFile(t, src, "osv/PyPI/PYSEC-2.json",
		`{"id":"PYSEC-2","aliases":["CVE-2024-0002"],"summary":"py 2"}`)
	writeFile(t, src, "osv/Go/GO-2024-9000.json",
		`{"id":"GO-2024-9000","summary":"go 1"}`)
	return cacheDir
}

// TestDebugUnify_SamplePicksFirstNLexicographically pins the
// reproducibility contract: --sample N must always pick the same N
// PrimaryIDs given the same sources tree (no random sampling). The
// order also defines what the validator sees when running the command
// repeatedly, so the contract is observable in the output.
func TestDebugUnify_SamplePicksFirstNLexicographically(t *testing.T) {
	cacheDir := sampleFixture(t)
	stdout, _, err := runDebugUnify(t, "--cache-dir", cacheDir, "--sample", "2")
	if err != nil {
		t.Fatalf("debug unify --sample: %v", err)
	}
	// NDJSON: one minified UnifiedAdvisory per line.
	lines := splitNDJSON(stdout)
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2 (NDJSON):\n%s", len(lines), stdout)
	}
	wantIDs := []string{"CVE-2024-0001", "CVE-2024-0002"}
	for i, want := range wantIDs {
		var rec unified.UnifiedAdvisory
		if err := json.Unmarshal([]byte(lines[i]), &rec); err != nil {
			t.Fatalf("decode line %d: %v\n%s", i, err, lines[i])
		}
		if rec.PrimaryID != want {
			t.Errorf("line %d PrimaryID = %q, want %q", i, rec.PrimaryID, want)
		}
	}
}

func TestDebugUnify_SampleAndIDAreMutuallyExclusive(t *testing.T) {
	cacheDir := sampleFixture(t)
	_, _, err := runDebugUnify(t, "--cache-dir", cacheDir, "--id", "CVE-2024-0001", "--sample", "2")
	if err == nil {
		t.Fatal("expected error when --id and --sample are both supplied")
	}
}

// splitNDJSON peels off non-empty lines from buf so trailing newlines
// don't show up as ghost records. Used because cobra's stdout writer
// may flush an extra newline at end-of-command on some platforms.
func splitNDJSON(buf string) []string {
	var out []string
	for _, ln := range bytes.Split([]byte(buf), []byte("\n")) {
		if len(bytes.TrimSpace(ln)) == 0 {
			continue
		}
		out = append(out, string(ln))
	}
	return out
}
