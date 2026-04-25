// Package cve defines parser types for the MITRE CVE Record Format v5.
//
// All upstream fields are declared as typed Go fields so a parse + re-marshal
// round-trip preserves every key the upstream catalog emits. Free-form
// per-source blobs (`Metric.Other.Content`, `x_legacyV4Record`,
// `x_generator`) are kept as `json.RawMessage` rather than dropped.
package cve

import (
	"encoding/json"
	"time"
)

// Record is one CVE5 JSON file.
type Record struct {
	DataType    string      `json:"dataType,omitempty"`
	DataVersion string      `json:"dataVersion,omitempty"`
	CVEMetadata CVEMetadata `json:"cveMetadata"`
	Containers  Containers  `json:"containers"`
}

// CVEMetadata carries the canonical CVE-ID and lifecycle dates.
type CVEMetadata struct {
	CVEID             string    `json:"cveId"`
	AssignerOrgID     string    `json:"assignerOrgId,omitempty"`
	AssignerShortName string    `json:"assignerShortName,omitempty"`
	RequesterUserID   string    `json:"requesterUserId,omitempty"`
	Serial            int       `json:"serial,omitempty"`
	State             string    `json:"state,omitempty"`
	DateReserved      time.Time `json:"dateReserved,omitzero"`
	DatePublished     time.Time `json:"datePublished,omitzero"`
	DateUpdated       time.Time `json:"dateUpdated,omitzero"`
	DateRejected      time.Time `json:"dateRejected,omitzero"`
}

// Containers groups per-actor sub-records.
type Containers struct {
	CNA CNA   `json:"cna"`
	ADP []ADP `json:"adp,omitempty"`
}

// CNA holds the CVE Numbering Authority's record content. ADP records share
// the same shape with a different provider; both are modeled as Container.
type CNA = Container

// ADP is one Authorized Data Publisher container (e.g. CISA Vulnrichment).
type ADP = Container

// Container is the shared shape between CNA and ADP entries.
type Container struct {
	ProviderMetadata *ProviderMetadata `json:"providerMetadata,omitempty"`
	Title            string            `json:"title,omitempty"`
	Source           json.RawMessage   `json:"source,omitempty"`
	DatePublic       time.Time         `json:"datePublic,omitzero"`
	DateAssigned     time.Time         `json:"dateAssigned,omitzero"`
	Descriptions     []Description     `json:"descriptions,omitempty"`
	Affected         []Affected        `json:"affected,omitempty"`
	References       []Reference       `json:"references,omitempty"`
	Metrics          []Metric          `json:"metrics,omitempty"`
	ProblemTypes     []ProblemType     `json:"problemTypes,omitempty"`
	Solutions        []Description     `json:"solutions,omitempty"`
	Workarounds      []Description     `json:"workarounds,omitempty"`
	Exploits         []Description     `json:"exploits,omitempty"`
	Configurations   []Description     `json:"configurations,omitempty"`
	Impacts          []Impact          `json:"impacts,omitempty"`
	Credits          []Credit          `json:"credits,omitempty"`
	Timeline         []TimelineEntry   `json:"timeline,omitempty"`
	Tags             []string          `json:"tags,omitempty"`
	RejectedReasons  []Description     `json:"rejectedReasons,omitempty"`
	ReplacedBy       []string          `json:"replacedBy,omitempty"`
	CPEApplicability json.RawMessage   `json:"cpeApplicability,omitempty"`
	XGenerator       json.RawMessage   `json:"x_generator,omitempty"`
	XLegacyV4Record  json.RawMessage   `json:"x_legacyV4Record,omitempty"`
	XAffectedList    json.RawMessage   `json:"x_affectedList,omitempty"`
	XRedhatCweChain  json.RawMessage   `json:"x_redhatCweChain,omitempty"`
	XConverterErrors json.RawMessage   `json:"x_ConverterErrors,omitempty"`
	TaxonomyMappings []TaxonomyMapping `json:"taxonomyMappings,omitempty"`
}

// TaxonomyMapping is one external taxonomy reference (e.g. CWE -> CAPEC).
type TaxonomyMapping struct {
	TaxonomyName      string             `json:"taxonomyName,omitempty"`
	TaxonomyVersion   string             `json:"taxonomyVersion,omitempty"`
	TaxonomyRelations []TaxonomyRelation `json:"taxonomyRelations,omitempty"`
}

// TaxonomyRelation is one mapped relation under a TaxonomyMapping.
type TaxonomyRelation struct {
	TaxonomyID        string `json:"taxonomyId,omitempty"`
	RelationshipName  string `json:"relationshipName,omitempty"`
	RelationshipID    string `json:"relationshipId,omitempty"`
	RelationshipValue string `json:"relationshipValue,omitempty"`
}

// Impact is one entry under containers.cna.impacts.
type Impact struct {
	CapecID      string        `json:"capecId,omitempty"`
	Descriptions []Description `json:"descriptions,omitempty"`
}

// Credit is one entry under containers.cna.credits.
type Credit struct {
	Lang  string `json:"lang,omitempty"`
	Value string `json:"value,omitempty"`
	User  string `json:"user,omitempty"`
	Type  string `json:"type,omitempty"`
}

// TimelineEntry is one entry under containers.cna.timeline.
type TimelineEntry struct {
	Time  time.Time `json:"time,omitzero"`
	Lang  string    `json:"lang,omitempty"`
	Value string    `json:"value,omitempty"`
}

// ProviderMetadata identifies the org that wrote the container.
type ProviderMetadata struct {
	OrgID       string    `json:"orgId,omitempty"`
	ShortName   string    `json:"shortName,omitempty"`
	DateUpdated time.Time `json:"dateUpdated,omitzero"`
}

// Description is a localized free-form text. Reused by descriptions[],
// solutions[], workarounds[], exploits[].
type Description struct {
	Lang            string            `json:"lang"`
	Value           string            `json:"value"`
	SupportingMedia []SupportingMedia `json:"supportingMedia,omitempty"`
}

// SupportingMedia is a richer media block (HTML, image, etc.) attached to
// a Description. Base64 is a pointer so the explicit `false` from upstream
// is preserved (a non-pointer bool would be omitted by omitempty).
type SupportingMedia struct {
	Type   string `json:"type,omitempty"`
	Base64 *bool  `json:"base64,omitempty"`
	Value  string `json:"value,omitempty"`
}

// Affected describes one product affected by the vulnerability.
type Affected struct {
	Vendor          string           `json:"vendor,omitempty"`
	Product         string           `json:"product,omitempty"`
	CollectionURL   string           `json:"collectionURL,omitempty"`
	PackageName     string           `json:"packageName,omitempty"`
	PackageURL      string           `json:"packageURL,omitempty"`
	Repo            string           `json:"repo,omitempty"`
	Modules         []string         `json:"modules,omitempty"`
	Platforms       []string         `json:"platforms,omitempty"`
	ProgramFiles    []string         `json:"programFiles,omitempty"`
	Versions        []Version        `json:"versions,omitempty"`
	DefaultStatus   string           `json:"defaultStatus,omitempty"`
	CPEs            []string         `json:"cpes,omitempty"`
	ProgramRoutines []ProgramRoutine `json:"programRoutines,omitempty"`
}

// ProgramRoutine identifies a vulnerable function/routine inside one product.
type ProgramRoutine struct {
	Name string `json:"name"`
}

// Version is one entry in Affected.Versions.
type Version struct {
	Version         string   `json:"version,omitempty"`
	Status          string   `json:"status,omitempty"`
	LessThan        string   `json:"lessThan,omitempty"`
	LessThanOrEqual string   `json:"lessThanOrEqual,omitempty"`
	VersionType     string   `json:"versionType,omitempty"`
	Changes         []Change `json:"changes,omitempty"`
}

// Change is a fine-grained status transition inside one Version.
type Change struct {
	At     string `json:"at,omitempty"`
	Status string `json:"status,omitempty"`
}

// Reference is one external link, optionally tagged by category.
type Reference struct {
	URL  string   `json:"url"`
	Name string   `json:"name,omitempty"`
	Tags []string `json:"tags,omitempty"`
}

// Metric carries one severity assessment in any of CVSS v2.0 / v3.0 / v3.1
// / v4.0, plus an "other" fallback for SSVC / kev tags / etc.
type Metric struct {
	Format    string       `json:"format,omitempty"`
	Scenarios []Scenario   `json:"scenarios,omitempty"`
	CVSSv20   *CVSS        `json:"cvssV2_0,omitempty"`
	CVSSv2    *CVSS        `json:"cvssV2,omitempty"`
	CVSSv30   *CVSS        `json:"cvssV3_0,omitempty"`
	CVSSv31   *CVSS        `json:"cvssV3_1,omitempty"`
	CVSSv40   *CVSS        `json:"cvssV4_0,omitempty"`
	Other     *MetricOther `json:"other,omitempty"`
}

// Scenario is the (optional) context under which a Metric applies.
type Scenario struct {
	Lang  string `json:"lang,omitempty"`
	Value string `json:"value,omitempty"`
}

// CVSS is the union of CVSS schema versions for the fields wisteria reads.
// BaseScore / TemporalScore / EnvironmentalScore are *float64 so an explicit
// upstream value of 0.0 is preserved (a non-pointer float would be omitted
// by omitempty).
type CVSS struct {
	Version      string   `json:"version,omitempty"`
	VectorString string   `json:"vectorString,omitempty"`
	BaseScore    *float64 `json:"baseScore,omitempty"`
	BaseSeverity string   `json:"baseSeverity,omitempty"`
	// CVSS v3.0 / v3.1 base metrics.
	AttackVector          string `json:"attackVector,omitempty"`
	AttackComplexity      string `json:"attackComplexity,omitempty"`
	PrivilegesRequired    string `json:"privilegesRequired,omitempty"`
	UserInteraction       string `json:"userInteraction,omitempty"`
	Scope                 string `json:"scope,omitempty"`
	ConfidentialityImpact string `json:"confidentialityImpact,omitempty"`
	IntegrityImpact       string `json:"integrityImpact,omitempty"`
	AvailabilityImpact    string `json:"availabilityImpact,omitempty"`
	// CVSS v2.0 base metrics (different naming).
	AccessVector     string `json:"accessVector,omitempty"`
	AccessComplexity string `json:"accessComplexity,omitempty"`
	Authentication   string `json:"authentication,omitempty"`
	// CVSS temporal sub-scores (v2.0 / v3.0 / v3.1).
	ExploitCodeMaturity string   `json:"exploitCodeMaturity,omitempty"`
	RemediationLevel    string   `json:"remediationLevel,omitempty"`
	ReportConfidence    string   `json:"reportConfidence,omitempty"`
	TemporalScore       *float64 `json:"temporalScore,omitempty"`
	TemporalSeverity    string   `json:"temporalSeverity,omitempty"`
	// CVSS environmental sub-scores (v3.0 / v3.1).
	EnvironmentalScore            *float64 `json:"environmentalScore,omitempty"`
	EnvironmentalSeverity         string   `json:"environmentalSeverity,omitempty"`
	ConfidentialityRequirement    string   `json:"confidentialityRequirement,omitempty"`
	IntegrityRequirement          string   `json:"integrityRequirement,omitempty"`
	AvailabilityRequirement       string   `json:"availabilityRequirement,omitempty"`
	ModifiedAttackVector          string   `json:"modifiedAttackVector,omitempty"`
	ModifiedAttackComplexity      string   `json:"modifiedAttackComplexity,omitempty"`
	ModifiedPrivilegesRequired    string   `json:"modifiedPrivilegesRequired,omitempty"`
	ModifiedUserInteraction       string   `json:"modifiedUserInteraction,omitempty"`
	ModifiedScope                 string   `json:"modifiedScope,omitempty"`
	ModifiedConfidentialityImpact string   `json:"modifiedConfidentialityImpact,omitempty"`
	ModifiedIntegrityImpact       string   `json:"modifiedIntegrityImpact,omitempty"`
	ModifiedAvailabilityImpact    string   `json:"modifiedAvailabilityImpact,omitempty"`
	// CVSS v4.0 base metrics.
	AttackRequirements        string `json:"attackRequirements,omitempty"`
	VulnConfidentialityImpact string `json:"vulnConfidentialityImpact,omitempty"`
	VulnIntegrityImpact       string `json:"vulnIntegrityImpact,omitempty"`
	VulnAvailabilityImpact    string `json:"vulnAvailabilityImpact,omitempty"`
	SubConfidentialityImpact  string `json:"subConfidentialityImpact,omitempty"`
	SubIntegrityImpact        string `json:"subIntegrityImpact,omitempty"`
	SubAvailabilityImpact     string `json:"subAvailabilityImpact,omitempty"`
	// CVSS v4.0 supplemental metrics. Upstream uses PascalCase for some;
	// preserve verbatim.
	Safety                      string `json:"Safety,omitempty"`
	Automatable                 string `json:"Automatable,omitempty"`
	Recovery                    string `json:"Recovery,omitempty"`
	ValueDensity                string `json:"valueDensity,omitempty"`
	VulnerabilityResponseEffort string `json:"vulnerabilityResponseEffort,omitempty"`
	ProviderUrgency             string `json:"providerUrgency,omitempty"`
	ExploitMaturity             string `json:"exploitMaturity,omitempty"`
}

// MetricOther carries non-CVSS metrics (e.g. SSVC).
type MetricOther struct {
	Type    string          `json:"type,omitempty"`
	Content json.RawMessage `json:"content,omitempty"`
}

// ProblemType is one CWE / problem-type description block.
type ProblemType struct {
	Descriptions []ProblemDescription `json:"descriptions,omitempty"`
}

// ProblemDescription is one labeled problem-type entry.
type ProblemDescription struct {
	Type        string `json:"type,omitempty"`
	Lang        string `json:"lang,omitempty"`
	Description string `json:"description,omitempty"`
	CWEID       string `json:"cweId,omitempty"`
}
