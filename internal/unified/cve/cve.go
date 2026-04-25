// Package cve defines parser types for the MITRE CVE Record Format v5.
// Field names follow the upstream CVE5 schema; only the fields wisteria's
// pipeline reads are declared.
package cve

// Record is one CVE5 JSON file.
type Record struct {
	DataType    string      `json:"dataType,omitempty"`
	DataVersion string      `json:"dataVersion,omitempty"`
	CVEMetadata CVEMetadata `json:"cveMetadata"`
	Containers  Containers  `json:"containers"`
}

// CVEMetadata carries the canonical CVE-ID and lifecycle state.
type CVEMetadata struct {
	CVEID         string `json:"cveId"`
	AssignerOrgID string `json:"assignerOrgId,omitempty"`
	State         string `json:"state,omitempty"`
}

// Containers groups per-actor sub-records. Only the CNA container is read.
type Containers struct {
	CNA CNA `json:"cna"`
}

// CNA holds the CVE Numbering Authority's record content.
type CNA struct {
	Descriptions []Description `json:"descriptions,omitempty"`
	Affected     []Affected    `json:"affected,omitempty"`
	References   []Reference   `json:"references,omitempty"`
	Metrics      []Metric      `json:"metrics,omitempty"`
}

// Description is a localized free-form text.
type Description struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

// Affected describes one product affected by the vulnerability.
type Affected struct {
	Vendor        string    `json:"vendor,omitempty"`
	Product       string    `json:"product,omitempty"`
	Versions      []Version `json:"versions,omitempty"`
	DefaultStatus string    `json:"defaultStatus,omitempty"`
}

// Version is one entry in Affected.Versions.
type Version struct {
	Version         string `json:"version,omitempty"`
	Status          string `json:"status,omitempty"`
	LessThan        string `json:"lessThan,omitempty"`
	LessThanOrEqual string `json:"lessThanOrEqual,omitempty"`
	VersionType     string `json:"versionType,omitempty"`
}

// Reference is one external link, optionally tagged by category.
type Reference struct {
	URL  string   `json:"url"`
	Name string   `json:"name,omitempty"`
	Tags []string `json:"tags,omitempty"`
}

// Metric carries one severity assessment in any of CVSS v3.0 / v3.1 / v4.0.
// At most one CVSS field is populated per metric entry.
type Metric struct {
	Format  string `json:"format,omitempty"`
	CVSSv30 *CVSS  `json:"cvssV3_0,omitempty"`
	CVSSv31 *CVSS  `json:"cvssV3_1,omitempty"`
	CVSSv40 *CVSS  `json:"cvssV4_0,omitempty"`
}

// CVSS is the common shape across CVSS schema versions for the fields
// wisteria reads (version, vector, base score, base severity).
type CVSS struct {
	Version      string  `json:"version,omitempty"`
	VectorString string  `json:"vectorString,omitempty"`
	BaseScore    float64 `json:"baseScore,omitempty"`
	BaseSeverity string  `json:"baseSeverity,omitempty"`
}
