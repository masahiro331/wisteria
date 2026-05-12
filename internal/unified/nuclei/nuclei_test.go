package nuclei

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestParse_FullTemplate(t *testing.T) {
	src := []byte(`id: CVE-2021-44228
info:
  name: Apache Log4j RCE
  severity: critical
  tags: cve,cve2021,rce,log4j,oast
  reference:
    - https://logging.apache.org/log4j/2.x/security.html
    - https://nvd.nist.gov/vuln/detail/CVE-2021-44228
  classification:
    cve-id: CVE-2021-44228
    cwe-id: CWE-77
`)
	got, err := Parse(src)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want := Template{
		ID: "CVE-2021-44228",
		Info: Info{
			Name:     "Apache Log4j RCE",
			Severity: "critical",
			Tags:     StringList{"cve", "cve2021", "rce", "log4j", "oast"},
			Reference: StringList{
				"https://logging.apache.org/log4j/2.x/security.html",
				"https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
			},
			Classification: Classification{
				CVEID: StringList{"CVE-2021-44228"},
				CWEID: StringList{"CWE-77"},
			},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Parse mismatch\n got: %+v\nwant: %+v", got, want)
	}
}

func TestParse_TagsAsList(t *testing.T) {
	src := []byte(`id: x
info:
  name: x
  severity: low
  tags:
    - cve
    - rce
  classification:
    cve-id: CVE-2024-1
`)
	got, err := Parse(src)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	wantTags := StringList{"cve", "rce"}
	if !reflect.DeepEqual(got.Info.Tags, wantTags) {
		t.Errorf("Tags = %v, want %v", got.Info.Tags, wantTags)
	}
}

func TestParse_MultipleCVEIDs(t *testing.T) {
	src := []byte(`id: x
info:
  name: x
  severity: high
  classification:
    cve-id:
      - CVE-2024-1
      - CVE-2024-2
`)
	got, err := Parse(src)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want := StringList{"CVE-2024-1", "CVE-2024-2"}
	if !reflect.DeepEqual(got.Info.Classification.CVEID, want) {
		t.Errorf("CVEID = %v, want %v", got.Info.Classification.CVEID, want)
	}
}

func TestParse_NoClassification(t *testing.T) {
	src := []byte(`id: weak-tls
info:
  name: Weak TLS
  severity: medium
`)
	got, err := Parse(src)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(got.Info.Classification.CVEID) != 0 {
		t.Errorf("expected no CVE-IDs, got %v", got.Info.Classification.CVEID)
	}
}

func TestWalk_FindsTemplatesAndAttachesPath(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "http", "cves", "2021", "CVE-2021-44228.yaml"),
		`id: CVE-2021-44228
info:
  name: Log4j
  severity: critical
  classification:
    cve-id: CVE-2021-44228
`)
	mustWrite(t, filepath.Join(root, "http", "cves", "2024", "CVE-2024-1.yaml"),
		`id: CVE-2024-1
info:
  name: Sample
  severity: low
  classification:
    cve-id: CVE-2024-1
`)
	mustWrite(t, filepath.Join(root, "README.md"), "skip me")
	mustWrite(t, filepath.Join(root, "broken.yaml"), "id: x\ninfo:\n  name: no-cve\n  severity: low\n") // no classification

	got, err := Walk(context.Background(), root)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}

	// Walk preserves filesystem order; assert by content. The "no
	// classification" template must be skipped.
	if len(got) != 2 {
		t.Fatalf("expected 2 templates, got %d", len(got))
	}
	byID := map[string]Template{}
	for _, tpl := range got {
		byID[tpl.ID] = tpl
	}

	tpl, ok := byID["CVE-2021-44228"]
	if !ok {
		t.Fatal("CVE-2021-44228 missing")
	}
	wantPath := filepath.Join("http", "cves", "2021", "CVE-2021-44228.yaml")
	if tpl.Path != wantPath {
		t.Errorf("Path = %q, want %q", tpl.Path, wantPath)
	}
}

func TestWalk_RootMissing_NoOp(t *testing.T) {
	got, err := Walk(context.Background(), filepath.Join(t.TempDir(), "does-not-exist"))
	if err != nil {
		t.Fatalf("Walk on missing root: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty result, got %v", got)
	}
}

func TestWalk_SkipsNonRegularEntries(t *testing.T) {
	root := t.TempDir()
	// One real template that should be picked up.
	mustWrite(t, filepath.Join(root, "real.yaml"),
		`id: CVE-2024-1
info:
  name: Real
  severity: low
  classification:
    cve-id: CVE-2024-1
`)
	// A dangling symlink whose name has a YAML suffix. Without the
	// non-regular-file guard this would surface as a read error;
	// with it, Walk silently skips it the same way the OSV walker
	// skips non-regular entries.
	link := filepath.Join(root, "linked.yaml")
	if err := os.Symlink(filepath.Join(root, "does-not-exist.yaml"), link); err != nil {
		t.Skipf("symlink unsupported on this filesystem: %v", err)
	}

	got, err := Walk(context.Background(), root)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(got) != 1 || got[0].ID != "CVE-2024-1" {
		t.Errorf("expected only the real template, got %+v", got)
	}
}

func TestWalk_MalformedYAML_AbortsWithFileName(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "bad.yaml"), "id: [unterminated")
	_, err := Walk(context.Background(), root)
	if err == nil {
		t.Fatal("expected error on malformed YAML, got nil")
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}
