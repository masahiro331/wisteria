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

func TestUnmarshal_ADPContainerWithVulnrichment(t *testing.T) {
	const body = `{
		"cveMetadata": {"cveId": "CVE-2024-1234"},
		"containers": {
			"cna": {},
			"adp": [
				{
					"title": "CISA ADP Vulnrichment",
					"providerMetadata": {"orgId": "abc", "shortName": "CISA-ADP"},
					"x_adpType": "vulnrichment",
					"problemTypes": [{"descriptions": [{"type": "CWE", "cweId": "CWE-352", "lang": "en", "description": "CSRF"}]}],
					"metrics": [
						{"other": {"type": "ssvc", "content": {"role": "CISA Coordinator"}}}
					]
				}
			]
		}
	}`
	var got Record
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(got.Containers.ADP) != 1 {
		t.Fatalf("ADP len = %d", len(got.Containers.ADP))
	}
	adp := got.Containers.ADP[0]
	if adp.Title != "CISA ADP Vulnrichment" {
		t.Errorf("ADP title = %q", adp.Title)
	}
	if adp.XADPType != "vulnrichment" {
		t.Errorf("ADP x_adpType = %q", adp.XADPType)
	}
	if len(adp.ProblemTypes) != 1 || adp.ProblemTypes[0].Descriptions[0].CWEID != "CWE-352" {
		t.Errorf("ADP problemTypes = %#v", adp.ProblemTypes)
	}
	if len(adp.Metrics) != 1 || adp.Metrics[0].Other == nil || adp.Metrics[0].Other.Type != "ssvc" {
		t.Errorf("ADP metrics = %#v", adp.Metrics)
	}
}

func TestUnmarshal_CVSSv31FullAttributes(t *testing.T) {
	// Cover every base/temporal/environmental sub-attribute the schema declares.
	const body = `{
		"cveMetadata": {"cveId": "CVE-2024-1"},
		"containers": {"cna": {"metrics": [{
			"format": "CVSS",
			"cvssV3_1": {
				"version": "3.1",
				"vectorString": "CVSS:3.1/...",
				"baseScore": 9.8,
				"baseSeverity": "CRITICAL",
				"attackVector": "NETWORK",
				"attackComplexity": "LOW",
				"privilegesRequired": "NONE",
				"userInteraction": "NONE",
				"scope": "UNCHANGED",
				"confidentialityImpact": "HIGH",
				"integrityImpact": "HIGH",
				"availabilityImpact": "HIGH",
				"exploitCodeMaturity": "PROOF_OF_CONCEPT",
				"remediationLevel": "OFFICIAL_FIX",
				"reportConfidence": "CONFIRMED",
				"temporalScore": 8.5,
				"temporalSeverity": "HIGH",
				"environmentalScore": 9.0,
				"environmentalSeverity": "CRITICAL",
				"confidentialityRequirement": "HIGH",
				"integrityRequirement": "MEDIUM",
				"availabilityRequirement": "LOW",
				"modifiedAttackVector": "ADJACENT_NETWORK",
				"modifiedAttackComplexity": "HIGH",
				"modifiedPrivilegesRequired": "LOW",
				"modifiedUserInteraction": "REQUIRED",
				"modifiedScope": "CHANGED",
				"modifiedConfidentialityImpact": "LOW",
				"modifiedIntegrityImpact": "NONE",
				"modifiedAvailabilityImpact": "NONE"
			}
		}]}}
	}`
	var got Record
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	v := got.Containers.CNA.Metrics[0].CVSSv31
	if v == nil {
		t.Fatal("CVSSv31 nil")
	}
	if v.BaseScore == nil || *v.BaseScore != 9.8 {
		t.Errorf("BaseScore = %v", v.BaseScore)
	}
	if v.TemporalScore == nil || *v.TemporalScore != 8.5 {
		t.Errorf("TemporalScore = %v", v.TemporalScore)
	}
	if v.EnvironmentalScore == nil || *v.EnvironmentalScore != 9.0 {
		t.Errorf("EnvironmentalScore = %v", v.EnvironmentalScore)
	}
	if v.ModifiedScope != "CHANGED" || v.ModifiedAvailabilityImpact != "NONE" {
		t.Errorf("modified attrs = %+v", v)
	}
	if v.ConfidentialityRequirement != "HIGH" {
		t.Errorf("ConfidentialityRequirement = %q", v.ConfidentialityRequirement)
	}
}

func TestUnmarshal_CVSSv4FullAttributes(t *testing.T) {
	const body = `{
		"cveMetadata": {"cveId": "CVE-2024-2"},
		"containers": {"cna": {"metrics": [{
			"cvssV4_0": {
				"version": "4.0",
				"baseScore": 8.7,
				"vectorString": "CVSS:4.0/...",
				"attackRequirements": "NONE",
				"vulnConfidentialityImpact": "HIGH",
				"vulnIntegrityImpact": "HIGH",
				"vulnAvailabilityImpact": "HIGH",
				"subConfidentialityImpact": "LOW",
				"subIntegrityImpact": "NONE",
				"subAvailabilityImpact": "NONE",
				"modifiedSubConfidentialityImpact": "LOW",
				"modifiedSubIntegrityImpact": "LOW",
				"modifiedSubAvailabilityImpact": "NONE",
				"Safety": "NEGLIGIBLE",
				"Automatable": "NO",
				"Recovery": "AUTOMATIC",
				"valueDensity": "DIFFUSE",
				"vulnerabilityResponseEffort": "LOW",
				"providerUrgency": "RED",
				"exploitMaturity": "POC"
			}
		}]}}
	}`
	var got Record
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	v := got.Containers.CNA.Metrics[0].CVSSv40
	if v == nil {
		t.Fatal("CVSSv40 nil")
	}
	if v.ModifiedSubConfidentialityImpact != "LOW" || v.ModifiedSubIntegrityImpact != "LOW" || v.ModifiedSubAvailabilityImpact != "NONE" {
		t.Errorf("modifiedSub* = %+v", v)
	}
	if v.Safety != "NEGLIGIBLE" || v.Automatable != "NO" || v.ProviderUrgency != "RED" {
		t.Errorf("supplemental = %+v", v)
	}
}

func TestUnmarshal_CVSSv2BaseAttributes(t *testing.T) {
	const body = `{
		"cveMetadata": {"cveId": "CVE-2007-1"},
		"containers": {"cna": {"metrics": [{
			"cvssV2_0": {
				"version": "2.0",
				"baseScore": 7.5,
				"vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
				"accessVector": "NETWORK",
				"accessComplexity": "LOW",
				"authentication": "NONE"
			}
		}]}}
	}`
	var got Record
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	v := got.Containers.CNA.Metrics[0].CVSSv20
	if v == nil {
		t.Fatal("CVSSv20 nil")
	}
	if v.AccessVector != "NETWORK" || v.AccessComplexity != "LOW" || v.Authentication != "NONE" {
		t.Errorf("v2 attrs = %+v", v)
	}
}

func TestUnmarshal_CPEApplicabilityTree(t *testing.T) {
	const body = `{
		"cveMetadata": {"cveId": "CVE-2024-3"},
		"containers": {"cna": {
			"cpeApplicability": [{
				"operator": "OR",
				"nodes": [{
					"operator": "OR",
					"negate": false,
					"negated": false,
					"cpeMatch": [
						{
							"vulnerable": true,
							"criteria": "cpe:2.3:a:foo:bar:*:*:*:*:*:*:*:*",
							"versionStartIncluding": "1.0.0",
							"versionEndExcluding": "1.5.0"
						}
					]
				}]
			}]
		}}
	}`
	var got Record
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	apps := got.Containers.CNA.CPEApplicability
	if len(apps) != 1 || apps[0].Operator != "OR" {
		t.Fatalf("apps = %#v", apps)
	}
	node := apps[0].Nodes[0]
	if node.Operator != "OR" {
		t.Errorf("node operator = %q", node.Operator)
	}
	if node.Negate == nil || *node.Negate {
		t.Errorf("Negate = %v", node.Negate)
	}
	if node.Negated == nil || *node.Negated {
		t.Errorf("Negated = %v", node.Negated)
	}
	if len(node.CPEMatch) != 1 || node.CPEMatch[0].Criteria != "cpe:2.3:a:foo:bar:*:*:*:*:*:*:*:*" {
		t.Errorf("cpeMatch = %#v", node.CPEMatch)
	}
	if node.CPEMatch[0].Vulnerable == nil || !*node.CPEMatch[0].Vulnerable {
		t.Errorf("Vulnerable = %v", node.CPEMatch[0].Vulnerable)
	}
	if node.CPEMatch[0].VersionStartIncluding != "1.0.0" || node.CPEMatch[0].VersionEndExcluding != "1.5.0" {
		t.Errorf("version bounds = %#v", node.CPEMatch[0])
	}
}

func TestUnmarshal_CNAMetadataLikeFields(t *testing.T) {
	const body = `{
		"cveMetadata": {"cveId": "CVE-2024-4", "serial": 3, "requesterUserId": "u-1"},
		"containers": {"cna": {
			"source": {"discovery": "EXTERNAL", "advisory": "ADV-1"},
			"timeline": [{"time": "2024-04-01T00:00:00Z", "lang": "en", "value": "disclosed"}],
			"credits": [{"lang": "en", "value": "Alice", "type": "FINDER"}],
			"impacts": [{"capecId": "CAPEC-66", "descriptions": [{"lang": "en", "value": "SQL Injection"}]}],
			"taxonomyMappings": [{
				"taxonomyName": "ATTACK",
				"taxonomyVersion": "v14",
				"taxonomyRelations": [{"taxonomyId": "T1059", "relationshipName": "subTechniqueOf", "relationshipId": "T1059.001", "relationshipValue": "Maps to"}]
			}],
			"tags": ["disputed"],
			"replacedBy": ["CVE-2024-99"]
		}}
	}`
	var got Record
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got.CVEMetadata.Serial != 3 || got.CVEMetadata.RequesterUserID != "u-1" {
		t.Errorf("metadata = %+v", got.CVEMetadata)
	}
	cna := got.Containers.CNA
	if len(cna.Source) == 0 {
		t.Errorf("Source raw should be populated")
	}
	if len(cna.Timeline) != 1 || cna.Timeline[0].Value != "disclosed" {
		t.Errorf("Timeline = %#v", cna.Timeline)
	}
	if len(cna.Credits) != 1 || cna.Credits[0].Value != "Alice" {
		t.Errorf("Credits = %#v", cna.Credits)
	}
	if len(cna.Impacts) != 1 || cna.Impacts[0].CapecID != "CAPEC-66" {
		t.Errorf("Impacts = %#v", cna.Impacts)
	}
	if len(cna.TaxonomyMappings) != 1 {
		t.Fatalf("TaxonomyMappings len = %d", len(cna.TaxonomyMappings))
	}
	tm := cna.TaxonomyMappings[0]
	if tm.TaxonomyName != "ATTACK" || tm.TaxonomyRelations[0].RelationshipValue != "Maps to" {
		t.Errorf("TaxonomyMappings = %#v", tm)
	}
	if len(cna.Tags) != 1 || cna.Tags[0] != "disputed" {
		t.Errorf("Tags = %v", cna.Tags)
	}
	if len(cna.ReplacedBy) != 1 || cna.ReplacedBy[0] != "CVE-2024-99" {
		t.Errorf("ReplacedBy = %v", cna.ReplacedBy)
	}
}

func TestUnmarshal_TimestampAcceptsTimezoneless(t *testing.T) {
	// Some CVE records emit "2006-01-02T15:04:05" without Z; the Timestamp
	// wrapper must parse those as UTC instead of failing.
	const body = `{
		"cveMetadata": {"cveId": "CVE-2022-x"},
		"containers": {"cna": {"providerMetadata": {"dateUpdated": "2022-09-05T11:06:08"}}}
	}`
	var got Record
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got.Containers.CNA.ProviderMetadata.DateUpdated.IsZero() {
		t.Errorf("dateUpdated should not be zero")
	}
}

func TestUnmarshal_AffectedExtendedFields(t *testing.T) {
	const body = `{
		"cveMetadata": {"cveId": "CVE-2024-5"},
		"containers": {"cna": {"affected": [{
			"vendor": "ACME",
			"product": "Foo",
			"collectionURL": "https://github.com/foo",
			"packageName": "foo",
			"packageURL": "pkg:generic/foo",
			"repo": "https://github.com/foo/foo",
			"modules": ["m1"],
			"platforms": ["linux"],
			"programFiles": ["bin/foo"],
			"cpes": ["cpe:2.3:a:acme:foo:1.0:*:*:*:*:*:*:*"],
			"cpe": ["cpe:/a:acme:foo:1.0"],
			"x_edition": "LTS",
			"x_SWEdition": "Pro",
			"programRoutines": [{"name": "vulnerable_func"}]
		}]}}
	}`
	var got Record
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	a := got.Containers.CNA.Affected[0]
	if a.PackageURL != "pkg:generic/foo" || a.CollectionURL != "https://github.com/foo" {
		t.Errorf("URLs = %+v", a)
	}
	if len(a.CPEs) != 1 || len(a.CPE) != 1 {
		t.Errorf("CPEs = %v / CPE = %v", a.CPEs, a.CPE)
	}
	if a.XEdition != "LTS" || a.XSWEdition != "Pro" {
		t.Errorf("x_* = %+v", a)
	}
	if len(a.ProgramRoutines) != 1 || a.ProgramRoutines[0].Name != "vulnerable_func" {
		t.Errorf("ProgramRoutines = %#v", a.ProgramRoutines)
	}
	if len(a.Modules) != 1 || len(a.Platforms) != 1 || len(a.ProgramFiles) != 1 {
		t.Errorf("string slices: m=%v p=%v pf=%v", a.Modules, a.Platforms, a.ProgramFiles)
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
