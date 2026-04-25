package kev

import (
	"encoding/json"
	"testing"
	"time"
)

func TestUnmarshal_Catalog(t *testing.T) {
	const body = `{
		"title": "CISA Catalog of Known Exploited Vulnerabilities",
		"catalogVersion": "2026.04.24",
		"dateReleased": "2026-04-24T16:52:07.2233Z",
		"count": 2,
		"vulnerabilities": [
			{
				"cveID": "CVE-2025-29635",
				"vendorProject": "D-Link",
				"product": "DIR-823X",
				"vulnerabilityName": "D-Link DIR-823X Command Injection Vulnerability",
				"dateAdded": "2026-04-24",
				"shortDescription": "RCE via /goform/set_prohibiting.",
				"requiredAction": "Apply mitigations.",
				"dueDate": "2026-05-08",
				"knownRansomwareCampaignUse": "Unknown",
				"notes": "https://example/sap10469",
				"cwes": ["CWE-77"]
			},
			{
				"cveID": "CVE-2024-7399",
				"vendorProject": "Samsung",
				"product": "MagicINFO 9 Server",
				"vulnerabilityName": "Path Traversal",
				"dateAdded": "2026-04-24",
				"shortDescription": "Arbitrary file write.",
				"requiredAction": "Apply mitigations.",
				"dueDate": "2026-05-08",
				"knownRansomwareCampaignUse": "Known",
				"notes": "",
				"cwes": ["CWE-22", "CWE-73"]
			}
		]
	}`

	var got Catalog
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if got.Title != "CISA Catalog of Known Exploited Vulnerabilities" {
		t.Errorf("Title = %q", got.Title)
	}
	if got.CatalogVersion != "2026.04.24" {
		t.Errorf("CatalogVersion = %q", got.CatalogVersion)
	}
	if got.Count != 2 {
		t.Errorf("Count = %d", got.Count)
	}
	if len(got.Vulnerabilities) != 2 {
		t.Fatalf("len(Vulnerabilities) = %d, want 2", len(got.Vulnerabilities))
	}
	wantReleased := time.Date(2026, 4, 24, 16, 52, 7, 223300000, time.UTC)
	if !got.DateReleased.Equal(wantReleased) {
		t.Errorf("DateReleased = %s, want %s", got.DateReleased, wantReleased)
	}

	v0 := got.Vulnerabilities[0]
	if v0.CVEID != "CVE-2025-29635" {
		t.Errorf("v0.CVEID = %q", v0.CVEID)
	}
	wantAdded := time.Date(2026, 4, 24, 0, 0, 0, 0, time.UTC)
	if !v0.DateAdded.Equal(wantAdded) {
		t.Errorf("v0.DateAdded = %s, want %s", v0.DateAdded, wantAdded)
	}
	wantDue := time.Date(2026, 5, 8, 0, 0, 0, 0, time.UTC)
	if !v0.DueDate.Equal(wantDue) {
		t.Errorf("v0.DueDate = %s, want %s", v0.DueDate, wantDue)
	}
	if got, want := v0.CWEs, []string{"CWE-77"}; len(got) != len(want) || got[0] != want[0] {
		t.Errorf("v0.CWEs = %v, want %v", got, want)
	}

	v1 := got.Vulnerabilities[1]
	if v1.KnownRansomwareCampaignUse != "Known" {
		t.Errorf("v1.KnownRansomwareCampaignUse = %q", v1.KnownRansomwareCampaignUse)
	}
	if len(v1.CWEs) != 2 {
		t.Errorf("v1.CWEs len = %d, want 2", len(v1.CWEs))
	}
}

func TestUnmarshal_DateAdded_RejectsInvalidFormat(t *testing.T) {
	const body = `{"vulnerabilities":[{"cveID":"CVE-1","dateAdded":"not-a-date","dueDate":"2026-01-01"}]}`
	var got Catalog
	if err := json.Unmarshal([]byte(body), &got); err == nil {
		t.Fatal("expected error for malformed dateAdded, got nil")
	}
}

func TestUnmarshal_OmitsAbsentDates(t *testing.T) {
	// Some KEV-shaped fixtures may omit dueDate; an absent (not present) field
	// must leave the time.Time zero rather than fail. KEV in practice always
	// has both, but we don't want unmarshal to brittle on missing optional
	// strings.
	const body = `{"vulnerabilities":[{"cveID":"CVE-1","dateAdded":"2026-01-01"}]}`
	var got Catalog
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !got.Vulnerabilities[0].DueDate.IsZero() {
		t.Errorf("DueDate should be zero when absent, got %s", got.Vulnerabilities[0].DueDate)
	}
}
