package pipeline_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/masahiro331/wisteria/internal/unified/pipeline"
)

// writeFile is a copy of cmd_test.writeFile so the pipeline package
// stays independent of the cmd package. Lays one source file at
// <root>/sources/<rel>.
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

// pipelineFixture lays out a minimal sources/ tree under cacheDir and
// returns the cacheDir. Same shape as cmd/unify_test.go's unifyFixture
// so the end-to-end behavior we cover here matches the CLI test's
// expectations exactly.
func pipelineFixture(t *testing.T) string {
	t.Helper()
	cacheDir := t.TempDir()
	src := filepath.Join(cacheDir, "sources")
	writeFile(t, src, "osv/PyPI/PYSEC-2024-1.json",
		`{"id":"PYSEC-2024-1","aliases":["CVE-2024-0001"],"summary":"Python advisory",`+
			`"affected":[{"package":{"ecosystem":"PyPI","name":"dask"}}]}`)
	writeFile(t, src, "cve/cvelistV5-main/cves/2024/0xxx/CVE-2024-0001.json",
		`{"cveMetadata":{"cveId":"CVE-2024-0001"},"containers":{"cna":{"descriptions":[{"lang":"en","value":"CNA"}]}}}`)
	writeFile(t, src, "osv/Go/GO-2024-1234.json",
		`{"id":"GO-2024-1234","summary":"Go advisory"}`)
	return cacheDir
}

func TestRun_WritesBothBucketsAndAnnotates(t *testing.T) {
	cacheDir := pipelineFixture(t)
	src := filepath.Join(cacheDir, "sources")
	// Add a KEV entry so the Stage 4 wiring is exercised — without this
	// the annotator step is a no-op and we wouldn't catch a regression
	// where someone removed the annotator.RunAll call from pipeline.Run.
	writeFile(t, src, "kev/known_exploited_vulnerabilities.json", `{
		"title":"t","catalogVersion":"v","dateReleased":"2024-04-01T00:00:00Z","count":1,
		"vulnerabilities":[
			{"cveID":"CVE-2024-0001","vendorProject":"Acme","product":"Widget",
			 "vulnerabilityName":"x","dateAdded":"2024-03-01","shortDescription":"s",
			 "requiredAction":"r","dueDate":"2024-03-22","knownRansomwareCampaignUse":"Known",
			 "notes":"","cwes":[]}
		]
	}`)

	var buf bytes.Buffer
	if err := pipeline.Run(context.Background(), cacheDir, pipeline.Options{}, &buf); err != nil {
		t.Fatalf("pipeline.Run: %v", err)
	}

	cveFile := filepath.Join(cacheDir, "unified", "cve", "2024", "CVE-2024-0001.json")
	if _, err := os.Stat(cveFile); err != nil {
		t.Errorf("expected cve bucket file %s: %v", cveFile, err)
	}
	standaloneFile := filepath.Join(cacheDir, "unified", "standalone", "Go", "GO-2024-1234.json")
	if _, err := os.Stat(standaloneFile); err != nil {
		t.Errorf("expected standalone bucket file %s: %v", standaloneFile, err)
	}
	body, err := os.ReadFile(cveFile)
	if err != nil {
		t.Fatalf("read unified file: %v", err)
	}
	if !bytes.Contains(body, []byte(`"vendor_project": "Acme"`)) {
		t.Errorf("KEV not applied to unified file:\n%s", body)
	}

	// Stage 5 must leave a lookup index next to the record buckets so
	// pkg/db drivers can resolve aliases and packages without scanning.
	for _, rel := range []string{
		filepath.Join("index", "meta.json"),
		filepath.Join("index", "ids", "PYSEC-2024-1.json"),
		filepath.Join("index", "packages", "PyPI", "dask.json"),
	} {
		p := filepath.Join(cacheDir, "unified", rel)
		if _, err := os.Stat(p); err != nil {
			t.Errorf("expected index file %s: %v", p, err)
		}
	}

	// Stage progress lines must appear so the user sees what happened.
	out := buf.String()
	for _, want := range []string{"stage 1", "stage 2+3", "annotate", "stage 5"} {
		if !strings.Contains(out, want) {
			t.Errorf("pipeline output missing %q line; got:\n%s", want, out)
		}
	}
}

func TestRun_FailsFastOnBrokenSource(t *testing.T) {
	cacheDir := t.TempDir()
	src := filepath.Join(cacheDir, "sources")
	writeFile(t, src, "osv/PyPI/bad.json", `{not json`)

	if err := pipeline.Run(context.Background(), cacheDir, pipeline.Options{}, nil); err == nil {
		t.Fatal("expected error from malformed OSV file")
	}
}

func TestRun_NilWriterIsAccepted(t *testing.T) {
	cacheDir := pipelineFixture(t)
	if err := pipeline.Run(context.Background(), cacheDir, pipeline.Options{}, nil); err != nil {
		t.Fatalf("pipeline.Run with nil writer: %v", err)
	}
}
