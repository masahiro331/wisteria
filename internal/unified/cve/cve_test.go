package cve

import (
	"encoding/json"
	"testing"
)

func TestUnmarshal_FullCNA(t *testing.T) {
	const body = `{
		"dataType": "CVE_RECORD",
		"dataVersion": "5.1",
		"cveMetadata": {
			"cveId": "CVE-2024-3094",
			"assignerOrgId": "...",
			"state": "PUBLISHED"
		},
		"containers": {
			"cna": {
				"descriptions": [
					{"lang": "en", "value": "Malicious code in xz/liblzma."},
					{"lang": "ja", "value": "xz/liblzma 内の悪意あるコード。"}
				],
				"affected": [
					{
						"vendor": "tukaani",
						"product": "xz",
						"versions": [
							{"version": "5.6.0", "status": "affected"},
							{"version": "5.6.1", "status": "affected"}
						],
						"defaultStatus": "unknown"
					}
				],
				"references": [
					{"url": "https://www.openwall.com/lists/oss-security/2024/03/29/4", "tags": ["mailing-list"]},
					{"url": "https://nvd.nist.gov/vuln/detail/CVE-2024-3094"}
				],
				"metrics": [
					{
						"format": "CVSS",
						"cvssV3_1": {
							"version": "3.1",
							"vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
							"baseScore": 10.0,
							"baseSeverity": "CRITICAL"
						}
					}
				]
			}
		}
	}`

	var got Record
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if got.CVEMetadata.CVEID != "CVE-2024-3094" {
		t.Errorf("CVEID = %q", got.CVEMetadata.CVEID)
	}
	cna := got.Containers.CNA
	if len(cna.Descriptions) != 2 || cna.Descriptions[0].Lang != "en" {
		t.Errorf("Descriptions = %#v", cna.Descriptions)
	}
	if len(cna.Affected) != 1 {
		t.Fatalf("Affected len = %d", len(cna.Affected))
	}
	a0 := cna.Affected[0]
	if a0.Vendor != "tukaani" || a0.Product != "xz" {
		t.Errorf("Affected[0] = %#v", a0)
	}
	if len(a0.Versions) != 2 || a0.Versions[1].Version != "5.6.1" {
		t.Errorf("Versions = %#v", a0.Versions)
	}
	if len(cna.References) != 2 {
		t.Errorf("References len = %d", len(cna.References))
	}
	if got, want := cna.References[0].Tags, []string{"mailing-list"}; len(got) != 1 || got[0] != want[0] {
		t.Errorf("References[0].Tags = %v, want %v", got, want)
	}
	if len(cna.Metrics) != 1 || cna.Metrics[0].CVSSv31 == nil {
		t.Fatalf("Metrics = %#v", cna.Metrics)
	}
	if cna.Metrics[0].CVSSv31.BaseScore == nil || *cna.Metrics[0].CVSSv31.BaseScore != 10.0 {
		t.Errorf("BaseScore = %v", cna.Metrics[0].CVSSv31.BaseScore)
	}
	if cna.Metrics[0].CVSSv31.VectorString == "" {
		t.Errorf("VectorString empty")
	}
}

func TestUnmarshal_MissingCNAFieldsAreOptional(t *testing.T) {
	// Reserved/rejected CVE records have only cveMetadata and an empty
	// containers.cna; unmarshal must succeed.
	const body = `{
		"cveMetadata": {"cveId": "CVE-2099-9999", "state": "RESERVED"},
		"containers": {"cna": {}}
	}`
	var got Record
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got.CVEMetadata.CVEID != "CVE-2099-9999" {
		t.Errorf("CVEID = %q", got.CVEMetadata.CVEID)
	}
	if len(got.Containers.CNA.Descriptions) != 0 {
		t.Errorf("Descriptions should be empty")
	}
}

func TestUnmarshal_AcceptsCVSSv30AndV40(t *testing.T) {
	// Older records carry cvssV3_0; newer ones may carry cvssV4_0.
	const body = `{
		"cveMetadata": {"cveId": "CVE-2020-0001"},
		"containers": {"cna": {"metrics": [
			{"format": "CVSS", "cvssV3_0": {"version": "3.0", "baseScore": 7.5, "vectorString": "CVSS:3.0/..."}},
			{"format": "CVSS", "cvssV4_0": {"version": "4.0", "baseScore": 8.7, "vectorString": "CVSS:4.0/..."}}
		]}}
	}`
	var got Record
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	m := got.Containers.CNA.Metrics
	if len(m) != 2 {
		t.Fatalf("Metrics len = %d", len(m))
	}
	if m[0].CVSSv30 == nil || m[0].CVSSv30.BaseScore == nil || *m[0].CVSSv30.BaseScore != 7.5 {
		t.Errorf("CVSSv30 = %#v", m[0].CVSSv30)
	}
	if m[1].CVSSv40 == nil || m[1].CVSSv40.BaseScore == nil || *m[1].CVSSv40.BaseScore != 8.7 {
		t.Errorf("CVSSv40 = %#v", m[1].CVSSv40)
	}
}
