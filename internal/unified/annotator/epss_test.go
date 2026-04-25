package annotator_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/masahiro331/wisteria/internal/unified"
	"github.com/masahiro331/wisteria/internal/unified/annotator"
)

const epssCSV = `#model_version:v2025.03.14,score_date:2026-04-24T12:55:00Z
cve,epss,percentile
CVE-2024-0001,0.5,0.9
CVE-2024-9999,0.1,0.2
`

func writeEPSSCatalog(t *testing.T, sourcesRoot, body string) {
	t.Helper()
	dir := filepath.Join(sourcesRoot, "epss")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	path := filepath.Join(dir, "epss_scores-current.csv")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

func TestAnnotateEPSS_HappyPath(t *testing.T) {
	root := t.TempDir()
	sourcesRoot := filepath.Join(root, "sources")
	outDir := filepath.Join(root, "unified")

	writeEPSSCatalog(t, sourcesRoot, epssCSV)
	target := writeUnifiedCVE(t, outDir, "CVE-2024-0001")

	if err := annotator.AnnotateEPSS(context.Background(), sourcesRoot, outDir); err != nil {
		t.Fatalf("AnnotateEPSS: %v", err)
	}

	body, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var got unified.UnifiedAdvisory
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.EPSS == nil {
		t.Fatal("EPSS not attached")
	}
	if got.EPSS.Score != 0.5 || got.EPSS.Percentile != 0.9 {
		t.Errorf("score/percentile = %v/%v, want 0.5/0.9", got.EPSS.Score, got.EPSS.Percentile)
	}
	if got.EPSS.ModelVersion != "v2025.03.14" {
		t.Errorf("ModelVersion = %q", got.EPSS.ModelVersion)
	}
	if got.EPSS.ScoreDate != "2026-04-24T12:55:00Z" {
		t.Errorf("ScoreDate = %q", got.EPSS.ScoreDate)
	}
	if got.EPSS.From.Kind != unified.SourceEPSS {
		t.Errorf("From.Kind = %q", got.EPSS.From.Kind)
	}
	if got.EPSS.From.ID != "CVE-2024-0001" {
		t.Errorf("From.ID = %q", got.EPSS.From.ID)
	}
	if got.EPSS.From.Path != "epss/epss_scores-current.csv" {
		t.Errorf("From.Path = %q", got.EPSS.From.Path)
	}
}

func TestAnnotateEPSS_MissingUnifiedFileIsSkipped(t *testing.T) {
	root := t.TempDir()
	sourcesRoot := filepath.Join(root, "sources")
	outDir := filepath.Join(root, "unified")

	writeEPSSCatalog(t, sourcesRoot, epssCSV)
	// No unified files at all → all rows miss; must not error.

	if err := annotator.AnnotateEPSS(context.Background(), sourcesRoot, outDir); err != nil {
		t.Fatalf("AnnotateEPSS with no targets should not error: %v", err)
	}
}

func TestAnnotateEPSS_MissingCatalogIsNoOp(t *testing.T) {
	root := t.TempDir()
	sourcesRoot := filepath.Join(root, "sources")
	outDir := filepath.Join(root, "unified")
	target := writeUnifiedCVE(t, outDir, "CVE-2024-0001")

	if err := annotator.AnnotateEPSS(context.Background(), sourcesRoot, outDir); err != nil {
		t.Fatalf("AnnotateEPSS with absent catalog should be no-op: %v", err)
	}

	body, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var got unified.UnifiedAdvisory
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.EPSS != nil {
		t.Errorf("EPSS should remain nil when catalog absent, got %+v", got.EPSS)
	}
}

func TestAnnotateEPSS_MalformedRowErrors(t *testing.T) {
	root := t.TempDir()
	sourcesRoot := filepath.Join(root, "sources")
	outDir := filepath.Join(root, "unified")

	const bad = `#model_version:v1,score_date:2026-04-24T12:55:00Z
cve,epss,percentile
CVE-2024-0001,not-a-float,0.9
`
	writeEPSSCatalog(t, sourcesRoot, bad)
	if err := annotator.AnnotateEPSS(context.Background(), sourcesRoot, outDir); err == nil {
		t.Fatal("expected error for malformed EPSS row")
	}
}
