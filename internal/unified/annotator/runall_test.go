package annotator_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/masahiro331/wisteria/internal/unified"
	"github.com/masahiro331/wisteria/internal/unified/annotator"
)

// minimal exploitdb CSV (id 1 → CVE-2024-0001) sharing the header from
// exploitdb_test.go. Keep the row count to 1 so the assertions stay
// readable; per-stage parsing is already covered in exploitdb_test.go.
const runallExploitDBCSV = exploitdbHeader + "\n" +
	`1,exploits/x.txt,Demo,2024-01-01,author,remote,linux,,2024-01-01,,1,CVE-2024-0001,tag,,,,`

func TestRunAll_RunsAllThreeAnnotators(t *testing.T) {
	root := t.TempDir()
	sourcesRoot := filepath.Join(root, "sources")
	outDir := filepath.Join(root, "unified")

	writeKEVCatalog(t, sourcesRoot, kevCatalogJSON)
	writeEPSSCatalog(t, sourcesRoot, epssCSV)
	writeExploitDBCatalog(t, sourcesRoot, runallExploitDBCSV)
	target := writeUnifiedCVE(t, outDir, "CVE-2024-0001")

	var buf bytes.Buffer
	if err := annotator.RunAll(context.Background(), sourcesRoot, outDir, &buf); err != nil {
		t.Fatalf("RunAll: %v", err)
	}

	body, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var got unified.UnifiedAdvisory
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.KEV == nil {
		t.Error("KEV not attached")
	}
	if got.EPSS == nil {
		t.Error("EPSS not attached")
	}
	if len(got.Exploits) == 0 {
		t.Error("Exploits not attached")
	}

	// The progress writer should mention every stage so callers (cmd/unify,
	// cmd/debug/annotate) get the same per-stage timing line they had
	// before the refactor.
	out := buf.String()
	for _, want := range []string{"kev", "epss", "exploitdb"} {
		if !strings.Contains(out, want) {
			t.Errorf("RunAll output missing %q stage line; got:\n%s", want, out)
		}
	}
}

func TestRunAll_NilWriterIsAccepted(t *testing.T) {
	root := t.TempDir()
	sourcesRoot := filepath.Join(root, "sources")
	outDir := filepath.Join(root, "unified")
	writeUnifiedCVE(t, outDir, "CVE-2024-0001")
	// No catalogs at all → all three annotators are no-ops; passing
	// nil io.Writer must not panic. Some callers (tests, scripts) don't
	// want timing output.
	if err := annotator.RunAll(context.Background(), sourcesRoot, outDir, nil); err != nil {
		t.Fatalf("RunAll with nil writer: %v", err)
	}
}

func TestRunAll_StopsOnFirstError(t *testing.T) {
	root := t.TempDir()
	sourcesRoot := filepath.Join(root, "sources")
	outDir := filepath.Join(root, "unified")

	// Malformed KEV catalog → AnnotateKEV must abort and RunAll must
	// surface that error without proceeding to EPSS / ExploitDB.
	writeKEVCatalog(t, sourcesRoot, `{not json`)

	var buf bytes.Buffer
	err := annotator.RunAll(context.Background(), sourcesRoot, outDir, &buf)
	if err == nil {
		t.Fatal("expected RunAll to surface the KEV parse error")
	}
	if !strings.Contains(err.Error(), "kev") {
		t.Errorf("error should reference kev stage; got %v", err)
	}
}
