package osv

import (
	"encoding/json"
	"testing"
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
