package osv

import (
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// GHSA-derived ecosystems (Hex, NuGet, RubyGems, Pub, SwiftURL,
// GitHub Actions, Packagist) that share the same database_specific
// shape — but each ecosystem still gets its own concrete type so a
// future divergence (e.g. NuGet shipping a new key Hex never sees)
// can grow locally without rippling.

// ============================================================
// Hex
// ============================================================

type RecordHex struct {
	Record
	Affected         []AffectedHex `json:"affected,omitempty"`
	DatabaseSpecific TopHex        `json:"database_specific,omitzero"`
}

func (r *RecordHex) Base() *Record      { return &r.Record }
func (r *RecordHex) AffectedAny() []any { return affectedAny(r.Affected) }

type AffectedHex struct {
	AffectedBase
	Ranges            []RangeHex     `json:"ranges,omitempty"`
	EcosystemSpecific AffectedEcoHex `json:"ecosystem_specific,omitzero"`
	DatabaseSpecific  AffectedDBHex  `json:"database_specific,omitzero"`
}

type RangeHex struct{ RangeBase }

type TopHex struct {
	CAPECIDs         []string  `json:"capec_ids,omitempty"`
	CPEIDs           []string  `json:"cpe_ids,omitempty"`
	CWEIDs           []string  `json:"cwe_ids"`
	GitHubReviewed   bool      `json:"github_reviewed,omitempty"`
	GitHubReviewedAt time.Time `json:"github_reviewed_at,omitzero"`
	NVDPublishedAt   time.Time `json:"nvd_published_at,omitzero"`
	Severity         string    `json:"severity,omitempty"`
}

func (t TopHex) IsZero() bool {
	return t.CAPECIDs == nil && t.CPEIDs == nil && t.CWEIDs == nil &&
		!t.GitHubReviewed && t.GitHubReviewedAt.IsZero() && t.NVDPublishedAt.IsZero() &&
		t.Severity == ""
}

type AffectedEcoHex struct{}

func (AffectedEcoHex) IsZero() bool { return true }

type AffectedDBHex struct {
	LastKnownAffectedVersionRange string `json:"last_known_affected_version_range,omitempty"`
	Source                        string `json:"source,omitempty"`
}

func (a AffectedDBHex) IsZero() bool { return a == AffectedDBHex{} }

func NewRecordHex(r io.Reader) (*RecordHex, error) {
	var rec RecordHex
	if err := json.NewDecoder(r).Decode(&rec); err != nil {
		return nil, fmt.Errorf("osv: parse Hex: %w", err)
	}
	rec.Ecosystem = EcosystemHex
	return &rec, nil
}

// ============================================================
// NuGet
// ============================================================

type RecordNuGet struct {
	Record
	Affected         []AffectedNuGet `json:"affected,omitempty"`
	DatabaseSpecific TopNuGet        `json:"database_specific,omitzero"`
}

func (r *RecordNuGet) Base() *Record      { return &r.Record }
func (r *RecordNuGet) AffectedAny() []any { return affectedAny(r.Affected) }

type AffectedNuGet struct {
	AffectedBase
	Ranges            []RangeNuGet     `json:"ranges,omitempty"`
	EcosystemSpecific AffectedEcoNuGet `json:"ecosystem_specific,omitzero"`
	DatabaseSpecific  AffectedDBNuGet  `json:"database_specific,omitzero"`
}

type RangeNuGet struct{ RangeBase }

type TopNuGet struct {
	CWEIDs                   []string                 `json:"cwe_ids"`
	GitHubReviewed           bool                     `json:"github_reviewed,omitempty"`
	GitHubReviewedAt         time.Time                `json:"github_reviewed_at,omitzero"`
	MaliciousPackagesOrigins []NuGetMalPackagesOrigin `json:"malicious-packages-origins,omitempty"`
	NVDPublishedAt           time.Time                `json:"nvd_published_at,omitzero"`
	Severity                 string                   `json:"severity,omitempty"`
}

func (t TopNuGet) IsZero() bool {
	return t.CWEIDs == nil && !t.GitHubReviewed && t.GitHubReviewedAt.IsZero() &&
		t.MaliciousPackagesOrigins == nil && t.NVDPublishedAt.IsZero() && t.Severity == ""
}

type NuGetMalPackagesOrigin struct {
	ID           string                  `json:"id,omitempty"`
	ImportTime   time.Time               `json:"import_time,omitzero"`
	ModifiedTime time.Time               `json:"modified_time,omitzero"`
	Ranges       []NuGetMalPackagesRange `json:"ranges,omitempty"`
	SHA256       string                  `json:"sha256,omitempty"`
	Source       string                  `json:"source,omitempty"`
	Versions     []string                `json:"versions,omitempty"`
}

type NuGetMalPackagesRange struct {
	Events []Event `json:"events,omitempty"`
	Repo   string  `json:"repo,omitempty"`
	Type   string  `json:"type,omitempty"`
}

type AffectedEcoNuGet struct{}

func (AffectedEcoNuGet) IsZero() bool { return true }

type AffectedDBNuGet struct {
	LastKnownAffectedVersionRange string `json:"last_known_affected_version_range,omitempty"`
	Source                        string `json:"source,omitempty"`
}

func (a AffectedDBNuGet) IsZero() bool { return a == AffectedDBNuGet{} }

func NewRecordNuGet(r io.Reader) (*RecordNuGet, error) {
	var rec RecordNuGet
	if err := json.NewDecoder(r).Decode(&rec); err != nil {
		return nil, fmt.Errorf("osv: parse NuGet: %w", err)
	}
	rec.Ecosystem = EcosystemNuGet
	return &rec, nil
}

// ============================================================
// RubyGems
// ============================================================

type RecordRubyGems struct {
	Record
	Affected         []AffectedRubyGems `json:"affected,omitempty"`
	DatabaseSpecific TopRubyGems        `json:"database_specific,omitzero"`
}

func (r *RecordRubyGems) Base() *Record      { return &r.Record }
func (r *RecordRubyGems) AffectedAny() []any { return affectedAny(r.Affected) }

type AffectedRubyGems struct {
	AffectedBase
	Ranges            []RangeRubyGems     `json:"ranges,omitempty"`
	EcosystemSpecific AffectedEcoRubyGems `json:"ecosystem_specific,omitzero"`
	DatabaseSpecific  AffectedDBRubyGems  `json:"database_specific,omitzero"`
}

type RangeRubyGems struct{ RangeBase }

type TopRubyGems struct {
	CWEIDs                   []string                    `json:"cwe_ids"`
	GitHubReviewed           bool                        `json:"github_reviewed,omitempty"`
	GitHubReviewedAt         time.Time                   `json:"github_reviewed_at,omitzero"`
	MaliciousPackagesOrigins []RubyGemsMalPackagesOrigin `json:"malicious-packages-origins,omitempty"`
	NVDPublishedAt           time.Time                   `json:"nvd_published_at,omitzero"`
	Severity                 string                      `json:"severity,omitempty"`
}

func (t TopRubyGems) IsZero() bool {
	return t.CWEIDs == nil && !t.GitHubReviewed && t.GitHubReviewedAt.IsZero() &&
		t.MaliciousPackagesOrigins == nil && t.NVDPublishedAt.IsZero() && t.Severity == ""
}

type RubyGemsMalPackagesOrigin struct {
	ID           string                     `json:"id,omitempty"`
	ImportTime   time.Time                  `json:"import_time,omitzero"`
	ModifiedTime time.Time                  `json:"modified_time,omitzero"`
	Ranges       []RubyGemsMalPackagesRange `json:"ranges,omitempty"`
	SHA256       string                     `json:"sha256,omitempty"`
	Source       string                     `json:"source,omitempty"`
	Versions     []string                   `json:"versions,omitempty"`
}

type RubyGemsMalPackagesRange struct {
	Events []Event `json:"events,omitempty"`
	Repo   string  `json:"repo,omitempty"`
	Type   string  `json:"type,omitempty"`
}

type AffectedEcoRubyGems struct{}

func (AffectedEcoRubyGems) IsZero() bool { return true }

type AffectedDBRubyGems struct {
	LastKnownAffectedVersionRange string `json:"last_known_affected_version_range,omitempty"`
	Source                        string `json:"source,omitempty"`
}

func (a AffectedDBRubyGems) IsZero() bool { return a == AffectedDBRubyGems{} }

func NewRecordRubyGems(r io.Reader) (*RecordRubyGems, error) {
	var rec RecordRubyGems
	if err := json.NewDecoder(r).Decode(&rec); err != nil {
		return nil, fmt.Errorf("osv: parse RubyGems: %w", err)
	}
	rec.Ecosystem = EcosystemRubyGems
	return &rec, nil
}

// ============================================================
// Pub
// ============================================================

type RecordPub struct {
	Record
	Affected         []AffectedPub `json:"affected,omitempty"`
	DatabaseSpecific TopPub        `json:"database_specific,omitzero"`
}

func (r *RecordPub) Base() *Record      { return &r.Record }
func (r *RecordPub) AffectedAny() []any { return affectedAny(r.Affected) }

type AffectedPub struct {
	AffectedBase
	Ranges            []RangePub     `json:"ranges,omitempty"`
	EcosystemSpecific AffectedEcoPub `json:"ecosystem_specific,omitzero"`
	DatabaseSpecific  AffectedDBPub  `json:"database_specific,omitzero"`
}

type RangePub struct{ RangeBase }

type TopPub struct {
	CWEIDs           []string  `json:"cwe_ids"`
	GitHubReviewed   bool      `json:"github_reviewed,omitempty"`
	GitHubReviewedAt time.Time `json:"github_reviewed_at,omitzero"`
	NVDPublishedAt   time.Time `json:"nvd_published_at,omitzero"`
	Severity         string    `json:"severity,omitempty"`
}

func (t TopPub) IsZero() bool {
	return t.CWEIDs == nil && !t.GitHubReviewed && t.GitHubReviewedAt.IsZero() &&
		t.NVDPublishedAt.IsZero() && t.Severity == ""
}

type AffectedEcoPub struct{}

func (AffectedEcoPub) IsZero() bool { return true }

type AffectedDBPub struct {
	LastKnownAffectedVersionRange string `json:"last_known_affected_version_range,omitempty"`
	Source                        string `json:"source,omitempty"`
}

func (a AffectedDBPub) IsZero() bool { return a == AffectedDBPub{} }

func NewRecordPub(r io.Reader) (*RecordPub, error) {
	var rec RecordPub
	if err := json.NewDecoder(r).Decode(&rec); err != nil {
		return nil, fmt.Errorf("osv: parse Pub: %w", err)
	}
	rec.Ecosystem = EcosystemPub
	return &rec, nil
}

// ============================================================
// SwiftURL
// ============================================================

type RecordSwiftURL struct {
	Record
	Affected         []AffectedSwiftURL `json:"affected,omitempty"`
	DatabaseSpecific TopSwiftURL        `json:"database_specific,omitzero"`
}

func (r *RecordSwiftURL) Base() *Record      { return &r.Record }
func (r *RecordSwiftURL) AffectedAny() []any { return affectedAny(r.Affected) }

type AffectedSwiftURL struct {
	AffectedBase
	Ranges            []RangeSwiftURL     `json:"ranges,omitempty"`
	EcosystemSpecific AffectedEcoSwiftURL `json:"ecosystem_specific,omitzero"`
	DatabaseSpecific  AffectedDBSwiftURL  `json:"database_specific,omitzero"`
}

type RangeSwiftURL struct{ RangeBase }

type TopSwiftURL struct {
	CWEIDs           []string  `json:"cwe_ids"`
	GitHubReviewed   bool      `json:"github_reviewed,omitempty"`
	GitHubReviewedAt time.Time `json:"github_reviewed_at,omitzero"`
	NVDPublishedAt   time.Time `json:"nvd_published_at,omitzero"`
	Severity         string    `json:"severity,omitempty"`
}

func (t TopSwiftURL) IsZero() bool {
	return t.CWEIDs == nil && !t.GitHubReviewed && t.GitHubReviewedAt.IsZero() &&
		t.NVDPublishedAt.IsZero() && t.Severity == ""
}

type AffectedEcoSwiftURL struct{}

func (AffectedEcoSwiftURL) IsZero() bool { return true }

type AffectedDBSwiftURL struct {
	LastKnownAffectedVersionRange string `json:"last_known_affected_version_range,omitempty"`
	Source                        string `json:"source,omitempty"`
}

func (a AffectedDBSwiftURL) IsZero() bool { return a == AffectedDBSwiftURL{} }

func NewRecordSwiftURL(r io.Reader) (*RecordSwiftURL, error) {
	var rec RecordSwiftURL
	if err := json.NewDecoder(r).Decode(&rec); err != nil {
		return nil, fmt.Errorf("osv: parse SwiftURL: %w", err)
	}
	rec.Ecosystem = EcosystemSwiftURL
	return &rec, nil
}

// ============================================================
// GitHub Actions
// ============================================================

type RecordGitHubActions struct {
	Record
	Affected         []AffectedGitHubActions `json:"affected,omitempty"`
	DatabaseSpecific TopGitHubActions        `json:"database_specific,omitzero"`
}

func (r *RecordGitHubActions) Base() *Record      { return &r.Record }
func (r *RecordGitHubActions) AffectedAny() []any { return affectedAny(r.Affected) }

type AffectedGitHubActions struct {
	AffectedBase
	Ranges            []RangeGitHubActions     `json:"ranges,omitempty"`
	EcosystemSpecific AffectedEcoGitHubActions `json:"ecosystem_specific,omitzero"`
	DatabaseSpecific  AffectedDBGitHubActions  `json:"database_specific,omitzero"`
}

type RangeGitHubActions struct{ RangeBase }

type TopGitHubActions struct {
	CWEIDs           []string  `json:"cwe_ids"`
	GitHubReviewed   bool      `json:"github_reviewed,omitempty"`
	GitHubReviewedAt time.Time `json:"github_reviewed_at,omitzero"`
	NVDPublishedAt   time.Time `json:"nvd_published_at,omitzero"`
	Severity         string    `json:"severity,omitempty"`
}

func (t TopGitHubActions) IsZero() bool {
	return t.CWEIDs == nil && !t.GitHubReviewed && t.GitHubReviewedAt.IsZero() &&
		t.NVDPublishedAt.IsZero() && t.Severity == ""
}

type AffectedEcoGitHubActions struct{}

func (AffectedEcoGitHubActions) IsZero() bool { return true }

type AffectedDBGitHubActions struct {
	LastKnownAffectedVersionRange string `json:"last_known_affected_version_range,omitempty"`
	Source                        string `json:"source,omitempty"`
}

func (a AffectedDBGitHubActions) IsZero() bool { return a == AffectedDBGitHubActions{} }

func NewRecordGitHubActions(r io.Reader) (*RecordGitHubActions, error) {
	var rec RecordGitHubActions
	if err := json.NewDecoder(r).Decode(&rec); err != nil {
		return nil, fmt.Errorf("osv: parse GitHubActions: %w", err)
	}
	rec.Ecosystem = EcosystemGitHubActions
	return &rec, nil
}

// ============================================================
// Packagist
// ============================================================

type RecordPackagist struct {
	Record
	Affected         []AffectedPackagist `json:"affected,omitempty"`
	DatabaseSpecific TopPackagist        `json:"database_specific,omitzero"`
}

func (r *RecordPackagist) Base() *Record      { return &r.Record }
func (r *RecordPackagist) AffectedAny() []any { return affectedAny(r.Affected) }

type AffectedPackagist struct {
	AffectedBase
	Ranges            []RangePackagist     `json:"ranges,omitempty"`
	EcosystemSpecific AffectedEcoPackagist `json:"ecosystem_specific,omitzero"`
	DatabaseSpecific  AffectedDBPackagist  `json:"database_specific,omitzero"`
}

type RangePackagist struct {
	RangeBase
	DatabaseSpecific RangeDBPackagist `json:"database_specific,omitzero"`
}

type TopPackagist struct {
	CWEIDs           []string  `json:"cwe_ids"`
	GitHubReviewed   bool      `json:"github_reviewed,omitempty"`
	GitHubReviewedAt time.Time `json:"github_reviewed_at,omitzero"`
	NVDPublishedAt   time.Time `json:"nvd_published_at,omitzero"`
	Severity         string    `json:"severity,omitempty"`
}

func (t TopPackagist) IsZero() bool {
	return t.CWEIDs == nil && !t.GitHubReviewed && t.GitHubReviewedAt.IsZero() &&
		t.NVDPublishedAt.IsZero() && t.Severity == ""
}

type AffectedEcoPackagist struct{}

func (AffectedEcoPackagist) IsZero() bool { return true }

type AffectedDBPackagist struct {
	AffectedVersions              string `json:"affected_versions,omitempty"`
	LastKnownAffectedVersionRange string `json:"last_known_affected_version_range,omitempty"`
	Patched                       bool   `json:"patched,omitempty"`
	Source                        string `json:"source,omitempty"`
}

func (a AffectedDBPackagist) IsZero() bool { return a == AffectedDBPackagist{} }

type RangeDBPackagist struct {
	Constraint string `json:"constraint,omitempty"`
}

func (r RangeDBPackagist) IsZero() bool { return r == RangeDBPackagist{} }

func NewRecordPackagist(r io.Reader) (*RecordPackagist, error) {
	var rec RecordPackagist
	if err := json.NewDecoder(r).Decode(&rec); err != nil {
		return nil, fmt.Errorf("osv: parse Packagist: %w", err)
	}
	rec.Ecosystem = EcosystemPackagist
	return &rec, nil
}

// ============================================================
// crates.io
// ============================================================

type RecordCratesIO struct {
	Record
	Affected         []AffectedCratesIO `json:"affected,omitempty"`
	DatabaseSpecific TopCratesIO        `json:"database_specific,omitzero"`
}

func (r *RecordCratesIO) Base() *Record      { return &r.Record }
func (r *RecordCratesIO) AffectedAny() []any { return affectedAny(r.Affected) }

type AffectedCratesIO struct {
	AffectedBase
	Ranges            []RangeCratesIO     `json:"ranges,omitempty"`
	EcosystemSpecific AffectedEcoCratesIO `json:"ecosystem_specific,omitzero"`
	DatabaseSpecific  AffectedDBCratesIO  `json:"database_specific,omitzero"`
}

type RangeCratesIO struct{ RangeBase }

type TopCratesIO struct {
	CWEIDs                   []string                    `json:"cwe_ids"`
	GitHubReviewed           bool                        `json:"github_reviewed,omitempty"`
	GitHubReviewedAt         time.Time                   `json:"github_reviewed_at,omitzero"`
	License                  string                      `json:"license,omitempty"`
	MaliciousPackagesOrigins []CratesIOMalPackagesOrigin `json:"malicious-packages-origins,omitempty"`
	NVDPublishedAt           time.Time                   `json:"nvd_published_at,omitzero"`
	Severity                 string                      `json:"severity,omitempty"`
}

func (t TopCratesIO) IsZero() bool {
	return t.CWEIDs == nil && !t.GitHubReviewed && t.GitHubReviewedAt.IsZero() &&
		t.License == "" && t.MaliciousPackagesOrigins == nil &&
		t.NVDPublishedAt.IsZero() && t.Severity == ""
}

type CratesIOMalPackagesOrigin struct {
	ID           string                     `json:"id,omitempty"`
	ImportTime   time.Time                  `json:"import_time,omitzero"`
	ModifiedTime time.Time                  `json:"modified_time,omitzero"`
	Ranges       []CratesIOMalPackagesRange `json:"ranges,omitempty"`
	SHA256       string                     `json:"sha256,omitempty"`
	Source       string                     `json:"source,omitempty"`
	Versions     []string                   `json:"versions,omitempty"`
}

type CratesIOMalPackagesRange struct {
	Events []Event `json:"events,omitempty"`
	Repo   string  `json:"repo,omitempty"`
	Type   string  `json:"type,omitempty"`
}

type AffectedEcoCratesIO struct {
	AffectedFunctions []string         `json:"affected_functions"`
	Affects           *CratesIOAffects `json:"affects,omitempty"`
}

func (a AffectedEcoCratesIO) IsZero() bool {
	return a.AffectedFunctions == nil && a.Affects == nil
}

type CratesIOAffects struct {
	Arch      []string `json:"arch"`
	Functions []string `json:"functions"`
	OS        []string `json:"os"`
}

type AffectedDBCratesIO struct {
	Categories                    []string      `json:"categories,omitempty"`
	CVSS                          *CratesIOCVSS `json:"cvss,omitempty"`
	CWEs                          []CratesIOCWE `json:"cwes,omitempty"`
	Informational                 *string       `json:"informational"`
	LastKnownAffectedVersionRange string        `json:"last_known_affected_version_range,omitempty"`
	Source                        string        `json:"source,omitempty"`
}

func (a AffectedDBCratesIO) IsZero() bool {
	return a.Categories == nil && a.CVSS == nil && a.CWEs == nil &&
		a.Informational == nil && a.LastKnownAffectedVersionRange == "" && a.Source == ""
}

// CratesIOCVSS mirrors MavenCVSS's union shape — observed both as a
// CVSS vector string and as `{score, vectorString}` in crates.io.
type CratesIOCVSS struct {
	Score        float64 `json:"score"`
	VectorString *string `json:"vectorString"`
	Vector       string  `json:"-"`
}

func (c CratesIOCVSS) MarshalJSON() ([]byte, error) {
	if c.Vector != "" {
		return json.Marshal(c.Vector)
	}
	type tmp struct {
		Score        float64 `json:"score"`
		VectorString *string `json:"vectorString"`
	}
	return json.Marshal(tmp{Score: c.Score, VectorString: c.VectorString})
}

func (c *CratesIOCVSS) UnmarshalJSON(b []byte) error {
	if len(b) == 0 || string(b) == "null" {
		*c = CratesIOCVSS{}
		return nil
	}
	switch b[0] {
	case '"':
		var v string
		if err := json.Unmarshal(b, &v); err != nil {
			return err
		}
		*c = CratesIOCVSS{Vector: v}
		return nil
	case '{':
		var t struct {
			Score        float64 `json:"score"`
			VectorString *string `json:"vectorString"`
		}
		if err := json.Unmarshal(b, &t); err != nil {
			return err
		}
		*c = CratesIOCVSS{Score: t.Score, VectorString: t.VectorString}
		return nil
	default:
		return fmt.Errorf("CratesIOCVSS: unexpected JSON %q", b)
	}
}

type CratesIOCWE struct {
	CWEID       string `json:"cweId,omitempty"`
	Description string `json:"description,omitempty"`
	Name        string `json:"name,omitempty"`
}

func NewRecordCratesIO(r io.Reader) (*RecordCratesIO, error) {
	var rec RecordCratesIO
	if err := json.NewDecoder(r).Decode(&rec); err != nil {
		return nil, fmt.Errorf("osv: parse CratesIO: %w", err)
	}
	rec.Ecosystem = EcosystemCratesIO
	return &rec, nil
}
