package cmd_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/masahiro331/wisteria/cmd"
)

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

// unifyFixture lays out a minimal sources/ tree under cacheDir: one
// CVE-aliased OSV + matching CVE5 file (CVE bucket) and one standalone
// OSV (standalone bucket). End-to-end coverage for `wisteria unify`.
func unifyFixture(t *testing.T) string {
	t.Helper()
	cacheDir := t.TempDir()
	src := filepath.Join(cacheDir, "sources")
	writeFile(t, src, "osv/PyPI/PYSEC-2024-1.json",
		`{"id":"PYSEC-2024-1","aliases":["CVE-2024-0001"],"summary":"Python advisory"}`)
	writeFile(t, src, "cve/cvelistV5-main/cves/2024/0xxx/CVE-2024-0001.json",
		`{"cveMetadata":{"cveId":"CVE-2024-0001"},"containers":{"cna":{"descriptions":[{"lang":"en","value":"CNA"}]}}}`)
	writeFile(t, src, "osv/Go/GO-2024-1234.json",
		`{"id":"GO-2024-1234","summary":"Go advisory"}`)
	return cacheDir
}

func runUnify(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	root := cmd.NewRootCmd()
	full := append([]string{"unify"}, args...)
	root.SetArgs(full)
	var out, errBuf bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errBuf)
	err = root.ExecuteContext(context.Background())
	return out.String(), errBuf.String(), err
}

func TestUnifyCmd_WritesBothBuckets(t *testing.T) {
	cacheDir := unifyFixture(t)

	if _, _, err := runUnify(t, "--cache-dir", cacheDir); err != nil {
		t.Fatalf("unify: %v", err)
	}

	cveFile := filepath.Join(cacheDir, "unified", "cve", "2024", "CVE-2024-0001.json")
	if _, err := os.Stat(cveFile); err != nil {
		t.Errorf("expected cve bucket file %s: %v", cveFile, err)
	}
	standaloneFile := filepath.Join(cacheDir, "unified", "standalone", "Go", "GO-2024-1234.json")
	if _, err := os.Stat(standaloneFile); err != nil {
		t.Errorf("expected standalone bucket file %s: %v", standaloneFile, err)
	}
}

// TestUnifyCmd_AppliesStage4 covers the wiring between Stage 3 and the
// annotators: a fixture that contains both source files AND KEV / EPSS
// catalogs must produce a unified file with both signal fields set.
// Catches the regression where someone removes the AnnotateKEV /
// AnnotateEPSS calls from cmd/unify.go.
func TestUnifyCmd_AppliesStage4(t *testing.T) {
	cacheDir := unifyFixture(t)
	src := filepath.Join(cacheDir, "sources")
	writeFile(t, src, "kev/known_exploited_vulnerabilities.json", `{
		"title":"t","catalogVersion":"v","dateReleased":"2024-04-01T00:00:00Z","count":1,
		"vulnerabilities":[
			{"cveID":"CVE-2024-0001","vendorProject":"Acme","product":"Widget",
			 "vulnerabilityName":"x","dateAdded":"2024-03-01","shortDescription":"s",
			 "requiredAction":"r","dueDate":"2024-03-22","knownRansomwareCampaignUse":"Known",
			 "notes":"","cwes":[]}
		]
	}`)
	writeFile(t, src, "epss/epss_scores-current.csv",
		"#model_version:v1,score_date:2026-04-24T12:55:00Z\ncve,epss,percentile\nCVE-2024-0001,0.5,0.9\n")

	if _, _, err := runUnify(t, "--cache-dir", cacheDir); err != nil {
		t.Fatalf("unify: %v", err)
	}

	body, err := os.ReadFile(filepath.Join(cacheDir, "unified", "cve", "2024", "CVE-2024-0001.json"))
	if err != nil {
		t.Fatalf("read unified file: %v", err)
	}
	if !bytes.Contains(body, []byte(`"vendor_project": "Acme"`)) {
		t.Errorf("KEV not applied to unified file:\n%s", body)
	}
	if !bytes.Contains(body, []byte(`"score": 0.5`)) {
		t.Errorf("EPSS not applied to unified file:\n%s", body)
	}
}

func TestUnifyCmd_FailsFastOnBrokenSource(t *testing.T) {
	cacheDir := t.TempDir()
	src := filepath.Join(cacheDir, "sources")
	writeFile(t, src, "osv/PyPI/bad.json", `{not json`)

	_, _, err := runUnify(t, "--cache-dir", cacheDir)
	if err == nil {
		t.Fatal("expected error from malformed OSV file (production fail-fast)")
	}
}
