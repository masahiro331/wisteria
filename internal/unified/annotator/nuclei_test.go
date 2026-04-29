package annotator_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/masahiro331/wisteria/internal/unified"
	"github.com/masahiro331/wisteria/internal/unified/annotator"
)

// writeNucleiTemplate creates one YAML template under the nuclei
// source tree. relPath is relative to <sourcesRoot>/nuclei/nuclei-templates-main/
// (matching the layout the fetcher produces).
func writeNucleiTemplate(t *testing.T, sourcesRoot, relPath, body string) {
	t.Helper()
	full := filepath.Join(sourcesRoot, "nuclei", "nuclei-templates-main", relPath)
	if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

func TestAnnotateNuclei_HappyPath_SingleTemplate(t *testing.T) {
	root := t.TempDir()
	sourcesRoot := filepath.Join(root, "sources")
	outDir := filepath.Join(root, "unified")

	writeNucleiTemplate(t, sourcesRoot, "http/cves/2024/CVE-2024-0001.yaml",
		`id: CVE-2024-0001
info:
  name: Sample RCE
  severity: critical
  tags: cve,rce
  reference:
    - https://example.com/advisory
  classification:
    cve-id: CVE-2024-0001
    cwe-id: CWE-77
`)
	target := writeUnifiedCVE(t, outDir, "CVE-2024-0001")

	if err := annotator.AnnotateNuclei(context.Background(), sourcesRoot, outDir); err != nil {
		t.Fatalf("AnnotateNuclei: %v", err)
	}

	got := readUnified(t, target)
	if len(got.NucleiTemplates) != 1 {
		t.Fatalf("NucleiTemplates = %d, want 1", len(got.NucleiTemplates))
	}
	tpl := got.NucleiTemplates[0]
	if tpl.ID != "CVE-2024-0001" {
		t.Errorf("ID = %q", tpl.ID)
	}
	if tpl.Name != "Sample RCE" {
		t.Errorf("Name = %q", tpl.Name)
	}
	if tpl.Severity != "critical" {
		t.Errorf("Severity = %q", tpl.Severity)
	}
	if len(tpl.Tags) != 2 || tpl.Tags[0] != "cve" || tpl.Tags[1] != "rce" {
		t.Errorf("Tags = %v", tpl.Tags)
	}
	if len(tpl.References) != 1 || tpl.References[0] != "https://example.com/advisory" {
		t.Errorf("References = %v", tpl.References)
	}
	if tpl.From.Kind != unified.SourceNuclei {
		t.Errorf("From.Kind = %q", tpl.From.Kind)
	}
	wantPath := filepath.Join("nuclei", "nuclei-templates-main", "http", "cves", "2024", "CVE-2024-0001.yaml")
	if tpl.From.Path != wantPath {
		t.Errorf("From.Path = %q, want %q", tpl.From.Path, wantPath)
	}
	if tpl.From.ID != "CVE-2024-0001" {
		t.Errorf("From.ID = %q", tpl.From.ID)
	}
}

func TestAnnotateNuclei_OneTemplateFansOutToMultipleCVEs(t *testing.T) {
	root := t.TempDir()
	sourcesRoot := filepath.Join(root, "sources")
	outDir := filepath.Join(root, "unified")

	writeNucleiTemplate(t, sourcesRoot, "shared.yaml",
		`id: shared-detector
info:
  name: Shared Detector
  severity: high
  classification:
    cve-id:
      - CVE-2024-0001
      - CVE-2024-0002
`)
	t1 := writeUnifiedCVE(t, outDir, "CVE-2024-0001")
	t2 := writeUnifiedCVE(t, outDir, "CVE-2024-0002")

	if err := annotator.AnnotateNuclei(context.Background(), sourcesRoot, outDir); err != nil {
		t.Fatalf("AnnotateNuclei: %v", err)
	}

	for _, p := range []string{t1, t2} {
		got := readUnified(t, p)
		if len(got.NucleiTemplates) != 1 || got.NucleiTemplates[0].ID != "shared-detector" {
			t.Errorf("%s: NucleiTemplates = %v, want one with ID=shared-detector", p, got.NucleiTemplates)
		}
	}
}

func TestAnnotateNuclei_MultipleTemplatesPerCVEPreserveWalkOrder(t *testing.T) {
	root := t.TempDir()
	sourcesRoot := filepath.Join(root, "sources")
	outDir := filepath.Join(root, "unified")

	// Walk visits files in lexicographic order under each directory,
	// so a/ → b/ → c/. Annotator must surface that order.
	writeNucleiTemplate(t, sourcesRoot, "a/first.yaml",
		`id: alpha
info:
  name: alpha
  severity: low
  classification:
    cve-id: CVE-2024-0001
`)
	writeNucleiTemplate(t, sourcesRoot, "b/second.yaml",
		`id: beta
info:
  name: beta
  severity: low
  classification:
    cve-id: CVE-2024-0001
`)
	writeNucleiTemplate(t, sourcesRoot, "c/third.yaml",
		`id: gamma
info:
  name: gamma
  severity: low
  classification:
    cve-id: CVE-2024-0001
`)
	target := writeUnifiedCVE(t, outDir, "CVE-2024-0001")

	if err := annotator.AnnotateNuclei(context.Background(), sourcesRoot, outDir); err != nil {
		t.Fatalf("AnnotateNuclei: %v", err)
	}
	got := readUnified(t, target)
	if len(got.NucleiTemplates) != 3 {
		t.Fatalf("NucleiTemplates = %d, want 3", len(got.NucleiTemplates))
	}
	wantOrder := []string{"alpha", "beta", "gamma"}
	for i, want := range wantOrder {
		if got.NucleiTemplates[i].ID != want {
			t.Errorf("position %d: got %q, want %q", i, got.NucleiTemplates[i].ID, want)
		}
	}
}

func TestAnnotateNuclei_TemplateWithoutCVEIDIsSkipped(t *testing.T) {
	root := t.TempDir()
	sourcesRoot := filepath.Join(root, "sources")
	outDir := filepath.Join(root, "unified")

	// No classification.cve-id → no join key → must not fan out.
	writeNucleiTemplate(t, sourcesRoot, "weak-tls.yaml",
		`id: weak-tls
info:
  name: Weak TLS
  severity: medium
`)
	writeNucleiTemplate(t, sourcesRoot, "match.yaml",
		`id: match
info:
  name: m
  severity: low
  classification:
    cve-id: CVE-2024-0001
`)
	target := writeUnifiedCVE(t, outDir, "CVE-2024-0001")

	if err := annotator.AnnotateNuclei(context.Background(), sourcesRoot, outDir); err != nil {
		t.Fatalf("AnnotateNuclei: %v", err)
	}
	got := readUnified(t, target)
	if len(got.NucleiTemplates) != 1 || got.NucleiTemplates[0].ID != "match" {
		t.Errorf("NucleiTemplates = %v, want only ID=match", got.NucleiTemplates)
	}
}

func TestAnnotateNuclei_MissingTargetIsSkipped(t *testing.T) {
	root := t.TempDir()
	sourcesRoot := filepath.Join(root, "sources")
	outDir := filepath.Join(root, "unified")

	writeNucleiTemplate(t, sourcesRoot, "x.yaml",
		`id: orphan
info:
  name: o
  severity: low
  classification:
    cve-id: CVE-2024-9999
`)
	// No unified file for CVE-2024-9999.

	if err := annotator.AnnotateNuclei(context.Background(), sourcesRoot, outDir); err != nil {
		t.Fatalf("AnnotateNuclei: %v", err)
	}
}

func TestAnnotateNuclei_MissingTreeIsNoop(t *testing.T) {
	root := t.TempDir()
	sourcesRoot := filepath.Join(root, "sources")
	outDir := filepath.Join(root, "unified")
	target := writeUnifiedCVE(t, outDir, "CVE-2024-0001")

	if err := annotator.AnnotateNuclei(context.Background(), sourcesRoot, outDir); err != nil {
		t.Fatalf("AnnotateNuclei returned error on missing tree: %v", err)
	}
	got := readUnified(t, target)
	if got.NucleiTemplates != nil {
		t.Errorf("NucleiTemplates = %v, want nil (tree absent → no-op)", got.NucleiTemplates)
	}
}

func TestAnnotateNuclei_MalformedYAMLAborts(t *testing.T) {
	root := t.TempDir()
	sourcesRoot := filepath.Join(root, "sources")
	outDir := filepath.Join(root, "unified")

	writeNucleiTemplate(t, sourcesRoot, "broken.yaml", "id: [unterminated")
	if err := annotator.AnnotateNuclei(context.Background(), sourcesRoot, outDir); err == nil {
		t.Fatal("expected error on malformed YAML")
	}
}
