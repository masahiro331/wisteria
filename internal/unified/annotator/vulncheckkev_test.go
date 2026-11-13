package annotator_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/masahiro331/wisteria/internal/unified/annotator"
	"github.com/masahiro331/wisteria/pkg/advisory"
)

const vulncheckCatalogJSON = `[
  {
    "vendorProject": "Acme", "product": "Widget", "shortDescription": "RCE in Widget.",
    "vulnerabilityName": "Acme Widget RCE", "required_action": "Apply updates.",
    "knownRansomwareCampaignUse": "Known", "cve": ["CVE-2024-0001"], "cwes": ["CWE-94"],
    "vulncheck_xdb": [{"xdb_id": "x1", "xdb_url": "https://vulncheck.com/xdb/x1", "date_added": "2024-03-02T00:00:00Z",
      "exploit_type": "initial-access", "clone_ssh_url": "git@github.com:a/b.git"}],
    "vulncheck_reported_exploitation": [{"url": "https://example.com/report", "date_added": "2024-02-28T00:00:00Z"}],
    "reported_exploited_by_vulncheck_canaries": true,
    "dueDate": "2024-03-22T00:00:00Z", "cisa_date_added": "2024-03-01T00:00:00Z",
    "date_added": "2024-02-28T00:00:00Z", "updated_at": "2024-03-05T00:00:00Z", "_timestamp": "2026-11-13T00:00:00Z"
  },
  {
    "vendorProject": "Ghost", "product": "Phantom", "shortDescription": "", "vulnerabilityName": "no unified file",
    "required_action": "", "knownRansomwareCampaignUse": "Unknown", "cve": ["CVE-2024-9999"], "cwes": [],
    "vulncheck_xdb": [], "vulncheck_reported_exploitation": [], "reported_exploited_by_vulncheck_canaries": false,
    "date_added": "2024-03-02T00:00:00Z", "updated_at": "2024-03-02T00:00:00Z", "_timestamp": "2026-11-13T00:00:00Z"
  }
]`

func writeVulnCheckCatalog(t *testing.T, sourcesRoot, body string) {
	t.Helper()
	dir := filepath.Join(sourcesRoot, "vulncheck-kev")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "vulncheck_known_exploited_vulnerabilities.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readUnifiedFile(t *testing.T, path string) (advisory.UnifiedAdvisory, map[string]json.RawMessage) {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var rec advisory.UnifiedAdvisory
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &rec); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatal(err)
	}
	return rec, raw
}

func TestAnnotateVulnCheckKEV_SetsRecordAndKeepsKEV(t *testing.T) {
	root := t.TempDir()
	sourcesRoot, outDir := filepath.Join(root, "sources"), filepath.Join(root, "unified")
	writeKEVCatalog(t, sourcesRoot, kevCatalogJSON)
	writeVulnCheckCatalog(t, sourcesRoot, vulncheckCatalogJSON)
	target := writeUnifiedCVE(t, outDir, "CVE-2024-0001")
	if err := annotator.AnnotateKEV(context.Background(), sourcesRoot, outDir); err != nil {
		t.Fatal(err)
	}
	_, before := readUnifiedFile(t, target)

	if err := annotator.AnnotateVulnCheckKEV(context.Background(), sourcesRoot, outDir); err != nil {
		t.Fatalf("AnnotateVulnCheckKEV: %v", err)
	}
	got, after := readUnifiedFile(t, target)
	if !bytes.Equal(before["kev"], after["kev"]) {
		t.Errorf("kev changed:\nbefore %s\nafter  %s", before["kev"], after["kev"])
	}
	v := got.VulnCheckKEV
	if v == nil {
		t.Fatal("vulncheck_kev not attached")
	}
	if v.From != (advisory.Provenance{Kind: advisory.SourceVulnCheckKEV,
		Path: "vulncheck-kev/vulncheck_known_exploited_vulnerabilities.json", ID: "CVE-2024-0001"}) {
		t.Errorf("From = %+v", v.From)
	}
	if v.VendorProject != "Acme" || v.DateAdded != "2024-02-28T00:00:00Z" || v.CISADateAdded != "2024-03-01T00:00:00Z" ||
		v.DueDate != "2024-03-22T00:00:00Z" || !v.ReportedByCanaries || v.UpdatedAt == "" || v.Timestamp == "" {
		t.Errorf("record = %+v", v)
	}
	if len(v.XDB) != 1 || v.XDB[0].ID != "x1" || len(v.ReportedExploitation) != 1 || v.ReportedExploitation[0].URL != "https://example.com/report" {
		t.Errorf("xdb / reported = %+v / %+v", v.XDB, v.ReportedExploitation)
	}
}

func TestAnnotateVulnCheckKEV_MissingCatalogIsNoop(t *testing.T) {
	root := t.TempDir()
	outDir := filepath.Join(root, "unified")
	target := writeUnifiedCVE(t, outDir, "CVE-2024-0001")
	if err := annotator.AnnotateVulnCheckKEV(context.Background(), filepath.Join(root, "sources"), outDir); err != nil {
		t.Fatal(err)
	}
	if got, _ := readUnifiedFile(t, target); got.VulnCheckKEV != nil {
		t.Error("vulncheck_kev attached without a catalog")
	}
}

func TestAnnotateVulnCheckKEV_MissingTargetSkips(t *testing.T) {
	root := t.TempDir()
	sourcesRoot, outDir := filepath.Join(root, "sources"), filepath.Join(root, "unified")
	writeVulnCheckCatalog(t, sourcesRoot, vulncheckCatalogJSON)
	if err := annotator.AnnotateVulnCheckKEV(context.Background(), sourcesRoot, outDir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(outDir, "cve", "2024", "CVE-2024-9999.json")); !os.IsNotExist(err) {
		t.Errorf("a unified file was created for a missing target: %v", err)
	}
}

func TestAnnotateVulnCheckKEV_DuplicateCVEKeepsEarliest(t *testing.T) {
	root := t.TempDir()
	sourcesRoot, outDir := filepath.Join(root, "sources"), filepath.Join(root, "unified")
	writeVulnCheckCatalog(t, sourcesRoot, `[
	  {"vendorProject": "Late", "cve": ["CVE-2024-0001"], "date_added": "2024-05-01T00:00:00Z"},
	  {"vendorProject": "Early", "cve": ["CVE-2024-0001"], "date_added": "2024-02-01T00:00:00Z"}
	]`)
	target := writeUnifiedCVE(t, outDir, "CVE-2024-0001")
	if err := annotator.AnnotateVulnCheckKEV(context.Background(), sourcesRoot, outDir); err != nil {
		t.Fatal(err)
	}
	if got, _ := readUnifiedFile(t, target); got.VulnCheckKEV == nil || got.VulnCheckKEV.VendorProject != "Early" {
		t.Errorf("record = %+v, want the earliest entry", got.VulnCheckKEV)
	}
}

func TestAnnotateVulnCheckKEV_MalformedCatalogErrors(t *testing.T) {
	root := t.TempDir()
	sourcesRoot := filepath.Join(root, "sources")
	writeVulnCheckCatalog(t, sourcesRoot, `{"not": "an array"}`)
	if err := annotator.AnnotateVulnCheckKEV(context.Background(), sourcesRoot, filepath.Join(root, "unified")); err == nil {
		t.Error("want a parse error")
	}
}

// The public JSON keys of vulncheck_kev are snake_case, like kev.
func TestVulnCheckKEVRecord_JSONKeys(t *testing.T) {
	b, err := json.Marshal(advisory.VulnCheckKEVRecord{XDB: []advisory.VulnCheckXDB{{}}, ReportedExploitation: []advisory.VulnCheckReportedExploit{{}},
		DueDate: "d", CISADateAdded: "c"})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	want := []string{"cisa_date_added", "cwes", "date_added", "due_date", "from", "known_ransomware_campaign_use", "product",
		"reported_by_canaries", "reported_exploitation", "required_action", "short_description", "timestamp", "updated_at",
		"vendor_project", "vulnerability_name", "xdb"}
	if !reflect.DeepEqual(keys, want) {
		t.Errorf("keys = %v\nwant   %v", keys, want)
	}
	if !strings.Contains(string(b), `"xdb":[{"xdb_id":"","xdb_url":"","date_added":"","exploit_type":"","clone_ssh_url":""}]`) {
		t.Errorf("xdb shape = %s", b)
	}
}

func TestRunAll_VulnCheckKEVRunsAfterKEV(t *testing.T) {
	root := t.TempDir()
	sourcesRoot, outDir := filepath.Join(root, "sources"), filepath.Join(root, "unified")
	writeKEVCatalog(t, sourcesRoot, kevCatalogJSON)
	writeVulnCheckCatalog(t, sourcesRoot, vulncheckCatalogJSON)
	target := writeUnifiedCVE(t, outDir, "CVE-2024-0001")
	var buf bytes.Buffer
	if err := annotator.RunAll(context.Background(), sourcesRoot, outDir, &buf, ""); err != nil {
		t.Fatal(err)
	}
	if got, _ := readUnifiedFile(t, target); got.KEV == nil || got.VulnCheckKEV == nil {
		t.Errorf("kev = %v, vulncheck_kev = %v", got.KEV != nil, got.VulnCheckKEV != nil)
	}
	out := buf.String()
	k, v, e := strings.Index(out, "annotate kev:"), strings.Index(out, "annotate vulncheck-kev:"), strings.Index(out, "annotate epss:")
	if k < 0 || v < 0 || e < 0 || k >= v || v >= e {
		t.Errorf("stage order wrong:\n%s", out)
	}
}

// An undated duplicate does not displace a dated one, and a CVE listed twice
// inside one entry is one entry.
func TestAnnotateVulnCheckKEV_DuplicateIgnoresUndated(t *testing.T) {
	root := t.TempDir()
	sourcesRoot, outDir := filepath.Join(root, "sources"), filepath.Join(root, "unified")
	writeVulnCheckCatalog(t, sourcesRoot, `[
	  {"vendorProject": "Dated", "cve": ["CVE-2024-0001", "CVE-2024-0001"], "date_added": "2024-05-01T00:00:00Z"},
	  {"vendorProject": "Undated", "cve": ["CVE-2024-0001"], "date_added": ""}
	]`)
	target := writeUnifiedCVE(t, outDir, "CVE-2024-0001")
	if err := annotator.AnnotateVulnCheckKEV(context.Background(), sourcesRoot, outDir); err != nil {
		t.Fatal(err)
	}
	if got, _ := readUnifiedFile(t, target); got.VulnCheckKEV == nil || got.VulnCheckKEV.VendorProject != "Dated" {
		t.Errorf("record = %+v, want the dated entry", got.VulnCheckKEV)
	}
}

// Empty upstream arrays stay empty arrays, not null.
func TestAnnotateVulnCheckKEV_EmptyArraysStayArrays(t *testing.T) {
	root := t.TempDir()
	sourcesRoot, outDir := filepath.Join(root, "sources"), filepath.Join(root, "unified")
	writeVulnCheckCatalog(t, sourcesRoot, vulncheckCatalogJSON)
	target := writeUnifiedCVE(t, outDir, "CVE-2024-9999")
	if err := annotator.AnnotateVulnCheckKEV(context.Background(), sourcesRoot, outDir); err != nil {
		t.Fatal(err)
	}
	_, raw := readUnifiedFile(t, target)
	var v map[string]json.RawMessage
	if err := json.Unmarshal(raw["vulncheck_kev"], &v); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"xdb", "reported_exploitation", "cwes"} {
		if string(v[k]) != "[]" {
			t.Errorf("%s = %s, want []", k, v[k])
		}
	}
}
