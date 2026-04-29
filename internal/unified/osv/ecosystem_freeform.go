package osv

import (
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// Ecosystems whose database_specific blob carries a free-form
// CVE-style metadata payload (Generic, GIT) plus the remaining
// straggler ecosystems (Go, OSS-Fuzz, Root, npm).

// ============================================================
// Generic
// ============================================================

type RecordGeneric struct {
	Record
	Affected         []AffectedGeneric `json:"affected,omitempty"`
	DatabaseSpecific TopGeneric        `json:"database_specific,omitzero"`
}

func (r *RecordGeneric) Base() *Record { return &r.Record }

type AffectedGeneric struct {
	AffectedBase
	Ranges            []RangeGeneric     `json:"ranges,omitempty"`
	EcosystemSpecific AffectedEcoGeneric `json:"ecosystem_specific,omitzero"`
	DatabaseSpecific  AffectedDBGeneric  `json:"database_specific,omitzero"`
}

type RangeGeneric struct{ RangeBase }

type TopGeneric struct {
	CWE              *GenericCWE     `json:"CWE,omitempty"`
	URL              string          `json:"URL,omitempty"`
	Affects          string          `json:"affects,omitempty"`
	Award            *GenericAward   `json:"award,omitempty"`
	CNAAssigner      string          `json:"cna_assigner,omitempty"`
	CWEIDs           []string        `json:"cwe_ids,omitempty"`
	IsDisputed       bool            `json:"isDisputed,omitempty"`
	Issue            string          `json:"issue,omitempty"`
	LastAffected     string          `json:"last_affected,omitempty"`
	OSVGeneratedFrom string          `json:"osv_generated_from,omitempty"`
	Package          string          `json:"package,omitempty"`
	Severity         GenericSeverity `json:"severity,omitzero"`
	WWW              string          `json:"www,omitempty"`
}

func (t TopGeneric) IsZero() bool {
	return t.CWE == nil && t.URL == "" && t.Affects == "" && t.Award == nil &&
		t.CNAAssigner == "" && t.CWEIDs == nil && !t.IsDisputed && t.Issue == "" &&
		t.LastAffected == "" && t.OSVGeneratedFrom == "" && t.Package == "" &&
		t.Severity.IsZero() && t.WWW == ""
}

type GenericCWE struct {
	Desc string `json:"desc,omitempty"`
	ID   string `json:"id,omitempty"`
}

type GenericAward struct {
	Amount   string `json:"amount,omitempty"`
	Currency string `json:"currency,omitempty"`
}

// GenericSeverity round-trips both string ("Medium") and null
// variants observed in the upstream Generic bucket. Zero means absent.
type GenericSeverity struct {
	Set   bool
	Label string
}

func (s GenericSeverity) IsZero() bool { return !s.Set }

func (s GenericSeverity) MarshalJSON() ([]byte, error) {
	if !s.Set {
		return []byte("null"), nil
	}
	return json.Marshal(s.Label)
}

func (s *GenericSeverity) UnmarshalJSON(b []byte) error {
	if len(b) == 0 || string(b) == "null" {
		*s = GenericSeverity{}
		return nil
	}
	if b[0] != '"' {
		return fmt.Errorf("GenericSeverity: unexpected JSON %q", b)
	}
	var v string
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	*s = GenericSeverity{Set: true, Label: v}
	return nil
}

type AffectedEcoGeneric struct{}

func (AffectedEcoGeneric) IsZero() bool { return true }

type AffectedDBGeneric struct {
	Source             string                   `json:"source,omitempty"`
	UnresolvedRanges   []UnresolvedRange        `json:"unresolved_ranges,omitempty"`
	UnresolvedVersions []UnresolvedVersionRange `json:"unresolved_versions,omitempty"`
}

func (a AffectedDBGeneric) IsZero() bool {
	return a.Source == "" && a.UnresolvedRanges == nil && a.UnresolvedVersions == nil
}

// UnresolvedRange is the shape upstream uses for `unresolved_ranges` —
// no `type` field, just an `events` list. Generic-only.
type UnresolvedRange struct {
	Events []Event `json:"events,omitempty"`
}

// UnresolvedVersionRange — same as UnresolvedRange but with a `type`
// field that round-trips even when empty (Generic emits `"type": ""`
// for unmappable Go module versions).
type UnresolvedVersionRange struct {
	Events []Event `json:"events,omitempty"`
	Type   string  `json:"type"`
}

func NewRecordGeneric(r io.Reader) (*RecordGeneric, error) {
	var rec RecordGeneric
	if err := json.NewDecoder(r).Decode(&rec); err != nil {
		return nil, fmt.Errorf("osv: parse Generic: %w", err)
	}
	rec.Ecosystem = EcosystemGeneric
	return &rec, nil
}

// ============================================================
// GIT
// ============================================================

type RecordGIT struct {
	Record
	Affected         []AffectedGIT `json:"affected,omitempty"`
	DatabaseSpecific TopGIT        `json:"database_specific,omitzero"`
}

func (r *RecordGIT) Base() *Record { return &r.Record }

type AffectedGIT struct {
	AffectedBase
	Ranges            []RangeGIT     `json:"ranges,omitempty"`
	EcosystemSpecific AffectedEcoGIT `json:"ecosystem_specific,omitzero"`
	DatabaseSpecific  AffectedDBGIT  `json:"database_specific,omitzero"`
}

type RangeGIT struct {
	RangeBase
	DatabaseSpecific RangeDBGIT `json:"database_specific,omitzero"`
}

type TopGIT struct {
	CWE                      *GenericCWE            `json:"CWE,omitempty"`
	URL                      string                 `json:"URL,omitempty"`
	Affects                  string                 `json:"affects,omitempty"`
	Award                    *GenericAward          `json:"award,omitempty"`
	CAPECIDs                 []string               `json:"capec_ids,omitempty"`
	CNAAssigner              string                 `json:"cna_assigner,omitempty"`
	CPEIDs                   []string               `json:"cpe_ids,omitempty"`
	Cwe                      []string               `json:"cwe,omitempty"`
	CWEIDs                   []string               `json:"cwe_ids,omitempty"`
	HumanLink                string                 `json:"human_link,omitempty"`
	Issue                    string                 `json:"issue,omitempty"`
	LastAffected             string                 `json:"last_affected,omitempty"`
	MaliciousPackagesOrigins []GITMalPackagesOrigin `json:"malicious-packages-origins,omitempty"`
	OSV                      string                 `json:"osv,omitempty"`
	OSVGeneratedFrom         string                 `json:"osv_generated_from,omitempty"`
	Package                  string                 `json:"package,omitempty"`
	Severity                 GenericSeverity        `json:"severity,omitzero"`
	UnresolvedRanges         []GITUnresolvedRange   `json:"unresolved_ranges,omitempty"`
	WWW                      string                 `json:"www,omitempty"`
}

func (t TopGIT) IsZero() bool {
	return t.CWE == nil && t.URL == "" && t.Affects == "" && t.Award == nil &&
		t.CAPECIDs == nil && t.CNAAssigner == "" && t.CPEIDs == nil && t.Cwe == nil &&
		t.CWEIDs == nil && t.HumanLink == "" && t.Issue == "" && t.LastAffected == "" &&
		t.MaliciousPackagesOrigins == nil && t.OSV == "" && t.OSVGeneratedFrom == "" &&
		t.Package == "" && t.Severity.IsZero() && t.UnresolvedRanges == nil && t.WWW == ""
}

type GITMalPackagesOrigin struct {
	ID           string                `json:"id,omitempty"`
	ImportTime   time.Time             `json:"import_time,omitzero"`
	ModifiedTime time.Time             `json:"modified_time,omitzero"`
	Ranges       []GITMalPackagesRange `json:"ranges,omitempty"`
	SHA256       string                `json:"sha256,omitempty"`
	Source       string                `json:"source,omitempty"`
	Versions     []string              `json:"versions,omitempty"`
}

type GITMalPackagesRange struct {
	Events []Event `json:"events,omitempty"`
	Repo   string  `json:"repo,omitempty"`
	Type   string  `json:"type,omitempty"`
}

// GITUnresolvedRange is the per-CPE block GIT attaches to records the
// importer could not normalise into a Range — same shape as
// RangeDBGIT plus an optional events list.
type GITUnresolvedRange struct {
	CPE             string  `json:"cpe,omitempty"`
	Events          []Event `json:"events,omitempty"`
	ExtractedEvents []Event `json:"extracted_events,omitempty"`
	Source          string  `json:"source,omitempty"`
}

type AffectedEcoGIT struct {
	FixedRange      string          `json:"fixed_range,omitempty"`
	IntroducedRange string          `json:"introduced_range,omitempty"`
	OpamConstraint  string          `json:"opam_constraint,omitempty"`
	Severity        GenericSeverity `json:"severity,omitzero"`
	Urgency         string          `json:"urgency,omitempty"`
}

func (a AffectedEcoGIT) IsZero() bool {
	return a.FixedRange == "" && a.IntroducedRange == "" && a.OpamConstraint == "" &&
		a.Severity.IsZero() && a.Urgency == ""
}

type AffectedDBGIT struct {
	FixedRange              string                  `json:"fixed_range,omitempty"`
	IntroducedRange         string                  `json:"introduced_range,omitempty"`
	Source                  string                  `json:"source,omitempty"`
	UnresolvedRanges        []GITUnresolvedRange    `json:"unresolved_ranges,omitempty"`
	VanirSignatures         []AndroidVanirSignature `json:"vanir_signatures,omitempty"`
	VanirSignaturesModified time.Time               `json:"vanir_signatures_modified,omitzero"`
}

func (a AffectedDBGIT) IsZero() bool {
	return a.FixedRange == "" && a.IntroducedRange == "" && a.Source == "" &&
		a.UnresolvedRanges == nil && a.VanirSignatures == nil &&
		a.VanirSignaturesModified.IsZero()
}

type RangeDBGIT struct {
	CPE             GITRangeCPE `json:"cpe,omitzero"`
	ExtractedEvents []Event     `json:"extracted_events,omitempty"`
	Source          string      `json:"source,omitempty"`
	Versions        []Event     `json:"versions,omitempty"`
}

func (r RangeDBGIT) IsZero() bool {
	return r.CPE.IsZero() && r.ExtractedEvents == nil && r.Source == "" && r.Versions == nil
}

// GITRangeCPE round-trips both string and []string variants found
// upstream — most records emit a bare string, but advisories that
// match multiple CPEs ship an array.
type GITRangeCPE struct {
	Set    bool
	Single string
	Multi  []string
}

func (c GITRangeCPE) IsZero() bool { return !c.Set }

func (c GITRangeCPE) MarshalJSON() ([]byte, error) {
	if !c.Set {
		return []byte("null"), nil
	}
	if c.Multi != nil {
		return json.Marshal(c.Multi)
	}
	return json.Marshal(c.Single)
}

func (c *GITRangeCPE) UnmarshalJSON(b []byte) error {
	if len(b) == 0 || string(b) == "null" {
		*c = GITRangeCPE{}
		return nil
	}
	switch b[0] {
	case '"':
		var v string
		if err := json.Unmarshal(b, &v); err != nil {
			return err
		}
		*c = GITRangeCPE{Set: true, Single: v}
		return nil
	case '[':
		var v []string
		if err := json.Unmarshal(b, &v); err != nil {
			return err
		}
		*c = GITRangeCPE{Set: true, Multi: v}
		return nil
	default:
		return fmt.Errorf("GITRangeCPE: unexpected JSON %q", b)
	}
}

func NewRecordGIT(r io.Reader) (*RecordGIT, error) {
	var rec RecordGIT
	if err := json.NewDecoder(r).Decode(&rec); err != nil {
		return nil, fmt.Errorf("osv: parse GIT: %w", err)
	}
	rec.Ecosystem = EcosystemGIT
	return &rec, nil
}

// ============================================================
// Go
// ============================================================

type RecordGo struct {
	Record
	Affected         []AffectedGo `json:"affected,omitempty"`
	DatabaseSpecific TopGo        `json:"database_specific,omitzero"`
}

func (r *RecordGo) Base() *Record { return &r.Record }

type AffectedGo struct {
	AffectedBase
	Ranges            []RangeGo     `json:"ranges,omitempty"`
	EcosystemSpecific AffectedEcoGo `json:"ecosystem_specific,omitzero"`
	DatabaseSpecific  AffectedDBGo  `json:"database_specific,omitzero"`
}

type RangeGo struct{ RangeBase }

type TopGo struct {
	CWEIDs                   []string              `json:"cwe_ids,omitempty"`
	GitHubReviewed           bool                  `json:"github_reviewed,omitempty"`
	GitHubReviewedAt         time.Time             `json:"github_reviewed_at,omitzero"`
	MaliciousPackagesOrigins []GoMalPackagesOrigin `json:"malicious-packages-origins,omitempty"`
	NVDPublishedAt           time.Time             `json:"nvd_published_at,omitzero"`
	ReviewStatus             string                `json:"review_status,omitempty"`
	Severity                 string                `json:"severity,omitempty"`
	URL                      string                `json:"url,omitempty"`
}

func (t TopGo) IsZero() bool {
	return t.CWEIDs == nil && !t.GitHubReviewed && t.GitHubReviewedAt.IsZero() &&
		t.MaliciousPackagesOrigins == nil && t.NVDPublishedAt.IsZero() &&
		t.ReviewStatus == "" && t.Severity == "" && t.URL == ""
}

type GoMalPackagesOrigin struct {
	ID           string               `json:"id,omitempty"`
	ImportTime   time.Time            `json:"import_time,omitzero"`
	ModifiedTime time.Time            `json:"modified_time,omitzero"`
	Ranges       []GoMalPackagesRange `json:"ranges,omitempty"`
	SHA256       string               `json:"sha256,omitempty"`
	Source       string               `json:"source,omitempty"`
	Versions     []string             `json:"versions,omitempty"`
}

type GoMalPackagesRange struct {
	Events []Event `json:"events,omitempty"`
	Repo   string  `json:"repo,omitempty"`
	Type   string  `json:"type,omitempty"`
}

type AffectedEcoGo struct {
	CustomRanges []GoCustomRange `json:"custom_ranges,omitempty"`
	GOOS         []string        `json:"goos,omitempty"`
	Imports      []GoImport      `json:"imports,omitempty"`
	Severity     string          `json:"severity,omitempty"`
	Symbols      []string        `json:"symbols,omitempty"`
}

func (a AffectedEcoGo) IsZero() bool {
	return a.CustomRanges == nil && a.GOOS == nil && a.Imports == nil &&
		a.Severity == "" && a.Symbols == nil
}

type GoCustomRange struct {
	Events []Event `json:"events,omitempty"`
	Type   string  `json:"type,omitempty"`
}

type GoImport struct {
	GOARCH  []string `json:"goarch,omitempty"`
	GOOS    []string `json:"goos,omitempty"`
	Path    string   `json:"path,omitempty"`
	Symbols []string `json:"symbols,omitempty"`
}

type AffectedDBGo struct {
	LastKnownAffectedVersionRange string `json:"last_known_affected_version_range,omitempty"`
	Source                        string `json:"source,omitempty"`
	URL                           string `json:"url,omitempty"`
}

func (a AffectedDBGo) IsZero() bool { return a == AffectedDBGo{} }

func NewRecordGo(r io.Reader) (*RecordGo, error) {
	var rec RecordGo
	if err := json.NewDecoder(r).Decode(&rec); err != nil {
		return nil, fmt.Errorf("osv: parse Go: %w", err)
	}
	rec.Ecosystem = EcosystemGo
	return &rec, nil
}

// ============================================================
// OSS-Fuzz
// ============================================================

type RecordOSSFuzz struct {
	Record
	Affected         []AffectedOSSFuzz `json:"affected,omitempty"`
	DatabaseSpecific TopOSSFuzz        `json:"database_specific,omitzero"`
}

func (r *RecordOSSFuzz) Base() *Record { return &r.Record }

type AffectedOSSFuzz struct {
	AffectedBase
	Ranges            []RangeOSSFuzz     `json:"ranges,omitempty"`
	EcosystemSpecific AffectedEcoOSSFuzz `json:"ecosystem_specific,omitzero"`
	DatabaseSpecific  AffectedDBOSSFuzz  `json:"database_specific,omitzero"`
}

type RangeOSSFuzz struct{ RangeBase }

type TopOSSFuzz struct{}

func (TopOSSFuzz) IsZero() bool { return true }

type AffectedEcoOSSFuzz struct {
	FixedRange      string          `json:"fixed_range,omitempty"`
	IntroducedRange string          `json:"introduced_range,omitempty"`
	Severity        GenericSeverity `json:"severity,omitzero"`
}

func (a AffectedEcoOSSFuzz) IsZero() bool {
	return a.FixedRange == "" && a.IntroducedRange == "" && a.Severity.IsZero()
}

type AffectedDBOSSFuzz struct {
	FixedRange      string `json:"fixed_range,omitempty"`
	IntroducedRange string `json:"introduced_range,omitempty"`
	Source          string `json:"source,omitempty"`
}

func (a AffectedDBOSSFuzz) IsZero() bool { return a == AffectedDBOSSFuzz{} }

func NewRecordOSSFuzz(r io.Reader) (*RecordOSSFuzz, error) {
	var rec RecordOSSFuzz
	if err := json.NewDecoder(r).Decode(&rec); err != nil {
		return nil, fmt.Errorf("osv: parse OSS-Fuzz: %w", err)
	}
	rec.Ecosystem = EcosystemOSSFuzz
	return &rec, nil
}

// ============================================================
// Root
// ============================================================

type RecordRoot struct {
	Record
	Affected         []AffectedRoot `json:"affected,omitempty"`
	DatabaseSpecific TopRoot        `json:"database_specific,omitzero"`
}

func (r *RecordRoot) Base() *Record { return &r.Record }

type AffectedRoot struct {
	AffectedBase
	Ranges            []RangeRoot     `json:"ranges,omitempty"`
	EcosystemSpecific AffectedEcoRoot `json:"ecosystem_specific,omitzero"`
	DatabaseSpecific  AffectedDBRoot  `json:"database_specific,omitzero"`
}

type RangeRoot struct{ RangeBase }

type TopRoot struct {
	// All Root fields round-trip with their bare presence even when
	// empty (e.g. distro_version = "" on gobinary advisories), so
	// none of them get omitempty.
	Distro        string `json:"distro"`
	DistroVersion string `json:"distro_version"`
	Source        string `json:"source"`
}

func (t TopRoot) IsZero() bool { return t == TopRoot{} }

type AffectedEcoRoot struct{}

func (AffectedEcoRoot) IsZero() bool { return true }

type AffectedDBRoot struct {
	// Root affected DB fields round-trip even when empty (root_patch_version
	// = "" on gobinary advisories), so none of them get omitempty.
	AllFixedVersions   []string `json:"all_fixed_versions"`
	RootPatchVersion   string   `json:"root_patch_version"`
	RootPatched        bool     `json:"root_patched"`
	Source             string   `json:"source"`
	TotalFixedVersions int      `json:"total_fixed_versions"`
	UpstreamVersion    string   `json:"upstream_version"`
}

func (a AffectedDBRoot) IsZero() bool {
	return a.AllFixedVersions == nil && a.RootPatchVersion == "" && !a.RootPatched &&
		a.Source == "" && a.TotalFixedVersions == 0 && a.UpstreamVersion == ""
}

func NewRecordRoot(r io.Reader) (*RecordRoot, error) {
	var rec RecordRoot
	if err := json.NewDecoder(r).Decode(&rec); err != nil {
		return nil, fmt.Errorf("osv: parse Root: %w", err)
	}
	rec.Ecosystem = EcosystemRoot
	return &rec, nil
}

// ============================================================
// npm
// ============================================================

type RecordNpm struct {
	Record
	Affected         []AffectedNpm `json:"affected,omitempty"`
	DatabaseSpecific TopNpm        `json:"database_specific,omitzero"`
}

func (r *RecordNpm) Base() *Record { return &r.Record }

type AffectedNpm struct {
	AffectedBase
	Ranges            []RangeNpm     `json:"ranges,omitempty"`
	EcosystemSpecific AffectedEcoNpm `json:"ecosystem_specific,omitzero"`
	DatabaseSpecific  AffectedDBNpm  `json:"database_specific,omitzero"`
}

type RangeNpm struct{ RangeBase }

type TopNpm struct {
	CWEIDs                   []string               `json:"cwe_ids"`
	GitHubReviewed           bool                   `json:"github_reviewed,omitempty"`
	GitHubReviewedAt         time.Time              `json:"github_reviewed_at,omitzero"`
	IOCs                     *NpmIOCs               `json:"iocs,omitempty"`
	MaliciousPackagesOrigins []NpmMalPackagesOrigin `json:"malicious-packages-origins,omitempty"`
	NVDPublishedAt           time.Time              `json:"nvd_published_at,omitzero"`
	Severity                 string                 `json:"severity,omitempty"`
}

func (t TopNpm) IsZero() bool {
	return t.CWEIDs == nil && !t.GitHubReviewed && t.GitHubReviewedAt.IsZero() &&
		t.IOCs == nil && t.MaliciousPackagesOrigins == nil &&
		t.NVDPublishedAt.IsZero() && t.Severity == ""
}

type NpmIOCs struct {
	Domains []string `json:"domains,omitempty"`
	IPs     []string `json:"ips,omitempty"`
	Strings []string `json:"strings,omitempty"`
	URLs    []string `json:"urls,omitempty"`
}

type NpmMalPackagesOrigin struct {
	ID           string                `json:"id,omitempty"`
	ImportTime   time.Time             `json:"import_time,omitzero"`
	ModifiedTime time.Time             `json:"modified_time,omitzero"`
	Ranges       []NpmMalPackagesRange `json:"ranges,omitempty"`
	SHA256       string                `json:"sha256,omitempty"`
	Source       string                `json:"source,omitempty"`
	Versions     []string              `json:"versions,omitempty"`
}

type NpmMalPackagesRange struct {
	Events []Event `json:"events,omitempty"`
	Repo   string  `json:"repo,omitempty"`
	Type   string  `json:"type,omitempty"`
}

type AffectedEcoNpm struct{}

func (AffectedEcoNpm) IsZero() bool { return true }

type AffectedDBNpm struct {
	CVSS                          *NpmCVSS `json:"cvss,omitempty"`
	CWEs                          []NpmCWE `json:"cwes"`
	GHSA                          string   `json:"ghsa,omitempty"`
	LastKnownAffectedVersionRange string   `json:"last_known_affected_version_range,omitempty"`
	Source                        string   `json:"source,omitempty"`
}

func (a AffectedDBNpm) IsZero() bool {
	return a.CVSS == nil && a.CWEs == nil && a.GHSA == "" &&
		a.LastKnownAffectedVersionRange == "" && a.Source == ""
}

type NpmCVSS struct {
	Score        float64 `json:"score"`
	VectorString *string `json:"vectorString"`
}

type NpmCWE struct {
	CWEID       string `json:"cweId,omitempty"`
	Description string `json:"description,omitempty"`
	Name        string `json:"name,omitempty"`
}

func NewRecordNpm(r io.Reader) (*RecordNpm, error) {
	var rec RecordNpm
	if err := json.NewDecoder(r).Decode(&rec); err != nil {
		return nil, fmt.Errorf("osv: parse npm: %w", err)
	}
	rec.Ecosystem = EcosystemNpm
	return &rec, nil
}
