package vulncheckkev

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

func readFixture(t *testing.T) ([]byte, []Entry) {
	t.Helper()
	raw, err := os.ReadFile("testdata/catalog.json")
	if err != nil {
		t.Fatal(err)
	}
	entries, err := Read(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	return raw, entries
}

func TestRead_ParsesIdentityAndDates(t *testing.T) {
	_, entries := readFixture(t)
	if len(entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(entries))
	}
	e := entries[0]
	if e.VendorProject != "PHP Group" || e.Product != "PHP" || !reflect.DeepEqual(e.CVE, []string{"CVE-2024-4577"}) {
		t.Errorf("identity = %q %q %v", e.VendorProject, e.Product, e.CVE)
	}
	if e.DateAdded != "2024-06-07T00:00:00Z" || e.DueDate != "2024-07-03T00:00:00Z" || e.CISADateAdded != "2024-06-12T00:00:00Z" {
		t.Errorf("dates = %q %q %q", e.DateAdded, e.DueDate, e.CISADateAdded)
	}
	if e.UpdatedAt == "" || e.Timestamp == "" {
		t.Errorf("timestamps = %q %q", e.UpdatedAt, e.Timestamp)
	}
}

func TestRead_ParsesText(t *testing.T) {
	_, entries := readFixture(t)
	e := entries[0]
	if e.VulnerabilityName == "" || e.ShortDescription == "" || e.RequiredAction == "" {
		t.Errorf("text fields missing: %+v", e)
	}
	if e.KnownRansomwareCampaignUse != "Known" || !reflect.DeepEqual(e.CWEs, []string{"CWE-78"}) {
		t.Errorf("ransomware/cwes = %q %v", e.KnownRansomwareCampaignUse, e.CWEs)
	}
	if !e.ReportedByCanaries {
		t.Error("reported_exploited_by_vulncheck_canaries = false, want true")
	}
}

func TestRead_ParsesNestedArrays(t *testing.T) {
	_, entries := readFixture(t)
	e := entries[0]
	want := XDB{ID: "d89b163c7ba9", URL: "https://vulncheck.com/xdb/d89b163c7ba9", DateAdded: "2024-06-07T05:50:23Z",
		ExploitType: "initial-access", CloneSSHURL: "git@github.com:TAM-K592/CVE-2024-4577.git"}
	if len(e.XDB) != 2 || e.XDB[0] != want {
		t.Errorf("xdb = %+v", e.XDB)
	}
	if len(e.ReportedExploitation) != 2 || e.ReportedExploitation[0].URL == "" || e.ReportedExploitation[0].DateAdded == "" {
		t.Errorf("reported exploitation = %+v", e.ReportedExploitation)
	}
}

func TestRead_VulnCheckOnlyEntry(t *testing.T) {
	_, entries := readFixture(t)
	if v := entries[1]; v.CISADateAdded != "" || v.DueDate != "" || v.XDB == nil || len(v.XDB) != 0 {
		t.Errorf("VulnCheck-only entry = cisa %q due %q xdb %#v", v.CISADateAdded, v.DueDate, v.XDB)
	}
}

// Re-marshaling keeps every upstream key and value, including the empty
// arrays and the absent optional dates.
func TestRead_RoundTripKeepsEveryKey(t *testing.T) {
	raw, entries := readFixture(t)
	out, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	var want, got []map[string]any
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("round trip differs:\ngot  %s", out)
	}
}

func TestRead_RejectsNonArray(t *testing.T) {
	if _, err := Read(strings.NewReader(`{"data": []}`)); err == nil {
		t.Error("want an error for a non-array document")
	}
}
