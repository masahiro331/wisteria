package annotator_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/masahiro331/wisteria/internal/unified/annotator"
	"github.com/masahiro331/wisteria/pkg/advisory"
)

// kevCatalogJSON is a minimal KEV catalog matching the upstream shape.
// Two vulnerabilities: one whose unified file exists (gets annotated)
// and one whose unified file is absent (must be silently skipped).
const kevCatalogJSON = `{
  "title": "CISA Catalog of Known Exploited Vulnerabilities",
  "catalogVersion": "2024.04.01",
  "dateReleased": "2024-04-01T00:00:00.000Z",
  "count": 2,
  "vulnerabilities": [
    {
      "cveID": "CVE-2024-0001",
      "vendorProject": "Acme",
      "product": "Widget",
      "vulnerabilityName": "Acme Widget RCE",
      "dateAdded": "2024-03-01",
      "shortDescription": "Remote code execution in Widget.",
      "requiredAction": "Apply updates per vendor instructions.",
      "dueDate": "2024-03-22",
      "knownRansomwareCampaignUse": "Known",
      "notes": "https://example.com/advisory",
      "cwes": ["CWE-94"]
    },
    {
      "cveID": "CVE-2024-9999",
      "vendorProject": "Ghost",
      "product": "Phantom",
      "vulnerabilityName": "no-unified-file",
      "dateAdded": "2024-03-02",
      "shortDescription": "should be skipped.",
      "requiredAction": "n/a",
      "dueDate": "2024-03-23",
      "knownRansomwareCampaignUse": "Unknown",
      "notes": "",
      "cwes": []
    }
  ]
}`

func writeUnifiedCVE(t *testing.T, outDir, id string) string {
	t.Helper()
	year := id[4:8]
	dir := filepath.Join(outDir, "cve", year)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	path := filepath.Join(dir, id+".json")
	rec := advisory.UnifiedAdvisory{PrimaryID: id}
	body, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

func writeKEVCatalog(t *testing.T, sourcesRoot, body string) {
	t.Helper()
	dir := filepath.Join(sourcesRoot, "kev")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	path := filepath.Join(dir, "known_exploited_vulnerabilities.json")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

func TestAnnotateKEV_HappyPath(t *testing.T) {
	root := t.TempDir()
	sourcesRoot := filepath.Join(root, "sources")
	outDir := filepath.Join(root, "unified")

	writeKEVCatalog(t, sourcesRoot, kevCatalogJSON)
	target := writeUnifiedCVE(t, outDir, "CVE-2024-0001")

	if err := annotator.AnnotateKEV(context.Background(), sourcesRoot, outDir); err != nil {
		t.Fatalf("AnnotateKEV: %v", err)
	}

	body, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var got advisory.UnifiedAdvisory
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.KEV == nil {
		t.Fatal("KEV not attached")
	}
	if got.KEV.VendorProject != "Acme" || got.KEV.Product != "Widget" {
		t.Errorf("KEV vendor/product = %q/%q, want Acme/Widget", got.KEV.VendorProject, got.KEV.Product)
	}
	if got.KEV.DateAdded != "2024-03-01" || got.KEV.DueDate != "2024-03-22" {
		t.Errorf("KEV dates = %q/%q, want 2024-03-01/2024-03-22", got.KEV.DateAdded, got.KEV.DueDate)
	}
	if got.KEV.From.Kind != advisory.SourceKEV {
		t.Errorf("KEV.From.Kind = %q, want %q", got.KEV.From.Kind, advisory.SourceKEV)
	}
	if got.KEV.From.ID != "CVE-2024-0001" {
		t.Errorf("KEV.From.ID = %q, want CVE-2024-0001", got.KEV.From.ID)
	}
	// Path must be relative to sourcesRoot (walker convention), not absolute.
	if got.KEV.From.Path != "kev/known_exploited_vulnerabilities.json" {
		t.Errorf("KEV.From.Path = %q, want relative kev path", got.KEV.From.Path)
	}
}

func TestAnnotateKEV_MissingUnifiedFileIsSkipped(t *testing.T) {
	root := t.TempDir()
	sourcesRoot := filepath.Join(root, "sources")
	outDir := filepath.Join(root, "unified")

	writeKEVCatalog(t, sourcesRoot, kevCatalogJSON)
	// No unified file at all → both KEV entries miss; must not error.

	if err := annotator.AnnotateKEV(context.Background(), sourcesRoot, outDir); err != nil {
		t.Fatalf("AnnotateKEV with no targets should not error: %v", err)
	}
}

func TestAnnotateKEV_MissingCatalogIsNoOp(t *testing.T) {
	root := t.TempDir()
	sourcesRoot := filepath.Join(root, "sources")
	outDir := filepath.Join(root, "unified")
	target := writeUnifiedCVE(t, outDir, "CVE-2024-0001")

	if err := annotator.AnnotateKEV(context.Background(), sourcesRoot, outDir); err != nil {
		t.Fatalf("AnnotateKEV with absent catalog should be no-op: %v", err)
	}

	body, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var got advisory.UnifiedAdvisory
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.KEV != nil {
		t.Errorf("KEV should remain nil when catalog absent, got %+v", got.KEV)
	}
}

func TestAnnotateKEV_MalformedCatalogErrors(t *testing.T) {
	root := t.TempDir()
	sourcesRoot := filepath.Join(root, "sources")
	outDir := filepath.Join(root, "unified")

	writeKEVCatalog(t, sourcesRoot, `{not json`)

	if err := annotator.AnnotateKEV(context.Background(), sourcesRoot, outDir); err == nil {
		t.Fatal("expected error for malformed KEV catalog")
	}
}
