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
// OSV alias and a CVE5 record, plus a non-zero score on each side, so
// the JSON output exercises both mergeReferences (URL dedup, tag union)
// and mergeSeverities (priority-based dedup).
func unifyFixtureCacheDir(t *testing.T) string {
	t.Helper()
	cacheDir := t.TempDir()
	src := filepath.Join(cacheDir, "sources")
	writeFile(t, src, "osv/AlmaLinux/ALSA-1.json", `{
		"id": "ALSA-1",
		"aliases": ["CVE-2024-0001"],
		"references": [
			{"type": "ADVISORY", "url": "https://example.com/a/"}
		],
		"severity": [
			{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N"}
		]
	}`)
	writeFile(t, src, "cve/cvelistV5-main/cves/2024/0xxx/CVE-2024-0001.json", `{
		"cveMetadata": {"cveId": "CVE-2024-0001"},
		"containers": {
			"cna": {
				"references": [
					{"url": "HTTPS://Example.COM/a", "tags": ["vendor-advisory"]},
					{"url": "https://nvd.example/cve-2024-0001"}
				],
				"metrics": [
					{"cvssV3_1": {"vectorString": "CVSS:3.1/AV:N", "baseScore": 9.8}}
				]
			}
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

func TestDebugUnify_MergesAcrossOSVAndCVE(t *testing.T) {
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
		t.Errorf("PrimaryID = %q, want CVE-2024-0001", got.PrimaryID)
	}

	// References: 2 unique URLs after normalization (the OSV "/a/" and the
	// CVE "HTTPS://Example.COM/a" collapse).
	if len(got.References) != 2 {
		t.Fatalf("References len = %d, want 2: %#v", len(got.References), got.References)
	}
	if got.References[0].URL != "https://example.com/a" {
		t.Errorf("References[0].URL = %q", got.References[0].URL)
	}
	// Tag union: OSV "ADVISORY" + CVE "vendor-advisory".
	gotTags := got.References[0].Tags
	if len(gotTags) != 2 || gotTags[0] != "ADVISORY" || gotTags[1] != "vendor-advisory" {
		t.Errorf("References[0].Tags = %v, want [ADVISORY vendor-advisory]", gotTags)
	}

	// Severities: same Type+Vector across OSV and CVE collapses to 1; the
	// cve.mitre Provenance wins because it outranks osv.AlmaLinux.
	if len(got.Severities) != 1 {
		t.Fatalf("Severities len = %d, want 1: %#v", len(got.Severities), got.Severities)
	}
	if got.Severities[0].From.Kind != unified.SourceCVE {
		t.Errorf("Severities[0].From.Kind = %q, want cve", got.Severities[0].From.Kind)
	}

	// Provenances list has both sources.
	if len(got.Provenances) != 2 {
		t.Errorf("Provenances len = %d, want 2", len(got.Provenances))
	}
}

func TestDebugUnify_RequiresID(t *testing.T) {
	cacheDir := unifyFixtureCacheDir(t)
	_, _, err := runDebugUnify(t, "--cache-dir", cacheDir)
	if err == nil {
		t.Fatal("expected error when --id is missing")
	}
}

func TestDebugUnify_IDNotFound(t *testing.T) {
	cacheDir := unifyFixtureCacheDir(t)
	_, _, err := runDebugUnify(t, "--cache-dir", cacheDir, "--id", "CVE-9999-9999")
	if err == nil {
		t.Fatal("expected error for unknown PrimaryID")
	}
}
