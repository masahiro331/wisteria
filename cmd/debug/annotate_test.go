package debug_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/masahiro331/wisteria/cmd"
	"github.com/masahiro331/wisteria/pkg/advisory"
)

// runDebugAnnotate invokes the root command tree so persistent flag
// resolution (--cache-dir on root) matches the production CLI.
func runDebugAnnotate(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	root := cmd.NewRootCmd()
	full := append([]string{"debug", "annotate"}, args...)
	root.SetArgs(full)
	var out, errBuf bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errBuf)
	err = root.ExecuteContext(context.Background())
	return out.String(), errBuf.String(), err
}

func TestDebugAnnotate_AppliesKEVAndEPSS(t *testing.T) {
	cacheDir := t.TempDir()
	src := filepath.Join(cacheDir, "sources")
	out := filepath.Join(cacheDir, "unified")

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

	// Pre-existing unified file (Stage 3 output simulated).
	target := filepath.Join(out, "cve", "2024", "CVE-2024-0001.json")
	if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	body, _ := json.MarshalIndent(advisory.UnifiedAdvisory{PrimaryID: "CVE-2024-0001"}, "", "  ")
	if err := os.WriteFile(target, body, 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	if _, _, err := runDebugAnnotate(t, "--cache-dir", cacheDir); err != nil {
		t.Fatalf("debug annotate: %v", err)
	}

	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var rec advisory.UnifiedAdvisory
	if err := json.Unmarshal(got, &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rec.KEV == nil || rec.KEV.VendorProject != "Acme" {
		t.Errorf("KEV not applied: %+v", rec.KEV)
	}
	if rec.EPSS == nil || rec.EPSS.Score != 0.5 {
		t.Errorf("EPSS not applied: %+v", rec.EPSS)
	}
}
