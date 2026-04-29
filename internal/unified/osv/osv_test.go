package osv

import (
	"encoding/json"
	"testing"
	"time"
)

func TestUnmarshal_PYSEC_MultiAlias(t *testing.T) {
	const body = `{
		"id": "PYSEC-2021-872",
		"aliases": ["CVE-2021-42343", "GHSA-hwqr-f3v9-hwxr", "GHSA-j8fq-86c5-5v2r", "PYSEC-2021-387", "PYSEC-2021-871"],
		"summary": "Dask remote code execution.",
		"details": "Dask 2021.10.0 and earlier ...",
		"references": [
			{"type": "ADVISORY", "url": "https://github.com/dask/dask/security/advisories/GHSA-hwqr-f3v9-hwxr"},
			{"type": "FIX", "url": "https://github.com/dask/dask/commit/abcdef"}
		],
		"severity": [
			{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
		],
		"affected": [
			{
				"package": {"ecosystem": "PyPI", "name": "dask", "purl": "pkg:pypi/dask"},
				"ranges": [
					{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2021.10.0"}]}
				],
				"versions": ["2021.9.1", "2021.9.0"],
				"ecosystem_specific": {"foo": "bar"}
			}
		]
	}`

	var got Record
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if got.ID != "PYSEC-2021-872" {
		t.Errorf("ID = %q", got.ID)
	}
	if len(got.Aliases) != 5 || got.Aliases[0] != "CVE-2021-42343" {
		t.Errorf("Aliases = %v", got.Aliases)
	}
	if got.Summary == "" || got.Details == "" {
		t.Errorf("Summary/Details should be populated")
	}
	if len(got.References) != 2 || got.References[1].Type != "FIX" {
		t.Errorf("References = %#v", got.References)
	}
	if len(got.Severity) != 1 || got.Severity[0].Type != "CVSS_V3" {
		t.Errorf("Severity = %#v", got.Severity)
	}

	if len(got.Affected) != 1 {
		t.Fatalf("Affected len = %d", len(got.Affected))
	}
	a0 := got.Affected[0]
	if a0.Package.Ecosystem != "PyPI" || a0.Package.Name != "dask" {
		t.Errorf("Package = %#v", a0.Package)
	}
	if len(a0.Ranges) != 1 || a0.Ranges[0].Type != "ECOSYSTEM" {
		t.Errorf("Ranges = %#v", a0.Ranges)
	}
	if len(a0.Ranges[0].Events) != 2 || a0.Ranges[0].Events[0].Introduced != "0" || a0.Ranges[0].Events[1].Fixed != "2021.10.0" {
		t.Errorf("Events = %#v", a0.Ranges[0].Events)
	}
	if len(a0.Versions) != 2 {
		t.Errorf("Versions len = %d", len(a0.Versions))
	}
}

func TestUnmarshal_AlmaLinux_NoAliases(t *testing.T) {
	const body = `{
		"id": "ALBA-2019:0973",
		"summary": "Moderate: 389-ds-base bug fix and enhancement update",
		"details": "...",
		"affected": [{"package": {"ecosystem": "AlmaLinux:8", "name": "389-ds-base"}}]
	}`
	var got Record
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got.ID != "ALBA-2019:0973" {
		t.Errorf("ID = %q", got.ID)
	}
	if len(got.Aliases) != 0 {
		t.Errorf("Aliases should be empty when absent, got %v", got.Aliases)
	}
}

func TestUnmarshal_FullTopLevelMetadata(t *testing.T) {
	const body = `{
		"schema_version": "1.7.3",
		"id": "ALPINE-CVE-2009-3895",
		"published": "2009-11-20T18:30:00.327Z",
		"modified": "2025-11-19T05:57:42.162407Z",
		"withdrawn": "2025-11-20T00:00:00Z",
		"upstream": ["CVE-2009-3895"],
		"related": ["GHSA-xyz"],
		"credits": [
			{"name": "Checkmarx", "contact": ["a@b", "https://example"], "type": "FINDER"}
		],
		"database_specific": {"iocs": {"domains": ["example.com"]}}
	}`
	var got Record
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got.SchemaVersion != "1.7.3" {
		t.Errorf("SchemaVersion = %q", got.SchemaVersion)
	}
	wantPub := time.Date(2009, 11, 20, 18, 30, 0, 327000000, time.UTC)
	if !got.Published.Equal(wantPub) {
		t.Errorf("Published = %s, want %s", got.Published, wantPub)
	}
	if got.Withdrawn.IsZero() {
		t.Errorf("Withdrawn should be set")
	}
	if len(got.Upstream) != 1 || got.Upstream[0] != "CVE-2009-3895" {
		t.Errorf("Upstream = %v", got.Upstream)
	}
	if len(got.Related) != 1 {
		t.Errorf("Related = %v", got.Related)
	}
	if len(got.Credits) != 1 || got.Credits[0].Name != "Checkmarx" || got.Credits[0].Type != "FINDER" {
		t.Errorf("Credits = %#v", got.Credits)
	}
	if len(got.Credits[0].Contact) != 2 {
		t.Errorf("Contact = %v", got.Credits[0].Contact)
	}
	if len(got.DatabaseSpecific) == 0 {
		t.Errorf("DatabaseSpecific raw should be populated")
	}
}

func TestUnmarshal_AffectedSeverityAndRangeDatabaseSpecific(t *testing.T) {
	const body = `{
		"id": "x",
		"affected": [{
			"package": {"ecosystem": "PyPI", "name": "p"},
			"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N"}],
			"ranges": [{
				"type": "ECOSYSTEM",
				"events": [{"introduced": "0"}],
				"database_specific": {"source": "https://example/x"}
			}]
		}]
	}`
	var got Record
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	a := got.Affected[0]
	if len(a.Severity) != 1 || a.Severity[0].Type != "CVSS_V3" {
		t.Errorf("Affected[0].Severity = %#v", a.Severity)
	}
	if len(a.Ranges[0].DatabaseSpecific) == 0 {
		t.Errorf("Range.DatabaseSpecific raw should be populated")
	}
}

func TestUnmarshal_PreservesEcosystemSpecificAsRawJSON(t *testing.T) {
	// ecosystem_specific is a free-form object; we keep it as raw JSON so
	// later stages can re-marshal it untouched.
	const body = `{
		"id": "x",
		"affected": [{
			"package": {"ecosystem": "Go", "name": "example"},
			"ecosystem_specific": {"vendor": "ACME", "nested": {"a": 1}}
		}]
	}`
	var got Record
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	raw := string(got.Affected[0].EcosystemSpecific)
	if raw == "" {
		t.Fatal("EcosystemSpecific raw is empty")
	}
	// Round-trip: must unmarshal back to a map without loss.
	var back map[string]any
	if err := json.Unmarshal(got.Affected[0].EcosystemSpecific, &back); err != nil {
		t.Fatalf("re-unmarshal raw: %v", err)
	}
	if back["vendor"] != "ACME" {
		t.Errorf("vendor lost in round-trip: %v", back)
	}
}
