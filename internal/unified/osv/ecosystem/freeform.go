package ecosystem

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/masahiro331/wisteria/internal/unified/osv"
)

// Ecosystems whose database_specific blob carries a free-form
// CVE-style metadata payload (Generic, GIT) plus the remaining
// straggler ecosystems (Go, OSS-Fuzz, Root, npm).

// ============================================================
// Generic
// ============================================================

type RecordGeneric struct {
	osv.Record
	Affected         []AffectedGeneric `json:"affected,omitempty"`
	DatabaseSpecific TopGeneric        `json:"database_specific,omitzero"`
}

func (r *RecordGeneric) Base() *osv.Record  { return &r.Record }
func (r *RecordGeneric) AffectedAny() []any { return affectedAny(r.Affected) }

type AffectedGeneric struct {
	osv.AffectedBase
	Ranges            []RangeGeneric     `json:"ranges,omitempty"`
	EcosystemSpecific AffectedEcoGeneric `json:"ecosystem_specific,omitzero"`
	DatabaseSpecific  AffectedDBGeneric  `json:"database_specific,omitzero"`
}

type RangeGeneric struct{ osv.RangeBase }

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
	Events []osv.Event `json:"events,omitempty"`
}

// UnresolvedVersionRange — same as UnresolvedRange but with a `type`
// field that round-trips even when empty (Generic emits `"type": ""`
// for unmappable Go module versions).
type UnresolvedVersionRange struct {
	Events []osv.Event `json:"events,omitempty"`
	Type   string      `json:"type"`
}

func NewRecordGeneric(r io.Reader) (*RecordGeneric, error) {
	var rec RecordGeneric
	if err := json.NewDecoder(r).Decode(&rec); err != nil {
		return nil, fmt.Errorf("osv: parse Generic: %w", err)
	}
	rec.Ecosystem = osv.EcosystemGeneric
	return &rec, nil
}

// ============================================================
// GIT
// ============================================================

type RecordGIT struct {
	osv.Record
	Affected         []AffectedGIT `json:"affected,omitempty"`
	DatabaseSpecific TopGIT        `json:"database_specific,omitzero"`
}

func (r *RecordGIT) Base() *osv.Record  { return &r.Record }
func (r *RecordGIT) AffectedAny() []any { return affectedAny(r.Affected) }

type AffectedGIT struct {
	osv.AffectedBase
	Ranges            []RangeGIT     `json:"ranges,omitempty"`
	EcosystemSpecific AffectedEcoGIT `json:"ecosystem_specific,omitzero"`
	DatabaseSpecific  AffectedDBGIT  `json:"database_specific,omitzero"`
}

type RangeGIT struct {
	osv.RangeBase
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
	Events []osv.Event `json:"events,omitempty"`
	Repo   string      `json:"repo,omitempty"`
	Type   string      `json:"type,omitempty"`
}

// GITUnresolvedRange is the per-CPE block GIT attaches to records the
// importer could not normalise into a Range — same shape as
// RangeDBGIT plus an optional events list.
type GITUnresolvedRange struct {
	CPE             string      `json:"cpe,omitempty"`
	Events          []osv.Event `json:"events,omitempty"`
	ExtractedEvents []osv.Event `json:"extracted_events,omitempty"`
	Source          string      `json:"source,omitempty"`
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
	CPE             osv.StringOrList `json:"cpe,omitzero"`
	ExtractedEvents []osv.Event      `json:"extracted_events,omitempty"`
	Source          osv.StringOrList `json:"source,omitzero"`
	Versions        []osv.Event      `json:"versions,omitempty"`
}

func (r RangeDBGIT) IsZero() bool {
	return r.CPE.IsZero() && r.ExtractedEvents == nil && r.Source.IsZero() && r.Versions == nil
}

func NewRecordGIT(r io.Reader) (*RecordGIT, error) {
	var rec RecordGIT
	if err := json.NewDecoder(r).Decode(&rec); err != nil {
		return nil, fmt.Errorf("osv: parse GIT: %w", err)
	}
	rec.Ecosystem = osv.EcosystemGIT
	return &rec, nil
}

// ============================================================
// Go
// ============================================================

type RecordGo struct {
	osv.Record
	Affected         []AffectedGo `json:"affected,omitempty"`
	DatabaseSpecific TopGo        `json:"database_specific,omitzero"`
}

func (r *RecordGo) Base() *osv.Record  { return &r.Record }
func (r *RecordGo) AffectedAny() []any { return affectedAny(r.Affected) }

type AffectedGo struct {
	osv.AffectedBase
	Ranges            []RangeGo     `json:"ranges,omitempty"`
	EcosystemSpecific AffectedEcoGo `json:"ecosystem_specific,omitzero"`
	DatabaseSpecific  AffectedDBGo  `json:"database_specific,omitzero"`
}

type RangeGo struct{ osv.RangeBase }

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
	Events []osv.Event `json:"events,omitempty"`
	Repo   string      `json:"repo,omitempty"`
	Type   string      `json:"type,omitempty"`
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
	Events []osv.Event `json:"events,omitempty"`
	Type   string      `json:"type,omitempty"`
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
	rec.Ecosystem = osv.EcosystemGo
	return &rec, nil
}

// ============================================================
// OSS-Fuzz
// ============================================================

type RecordOSSFuzz struct {
	osv.Record
	Affected         []AffectedOSSFuzz `json:"affected,omitempty"`
	DatabaseSpecific TopOSSFuzz        `json:"database_specific,omitzero"`
}

func (r *RecordOSSFuzz) Base() *osv.Record  { return &r.Record }
func (r *RecordOSSFuzz) AffectedAny() []any { return affectedAny(r.Affected) }

type AffectedOSSFuzz struct {
	osv.AffectedBase
	Ranges            []RangeOSSFuzz     `json:"ranges,omitempty"`
	EcosystemSpecific AffectedEcoOSSFuzz `json:"ecosystem_specific,omitzero"`
	DatabaseSpecific  AffectedDBOSSFuzz  `json:"database_specific,omitzero"`
}

type RangeOSSFuzz struct{ osv.RangeBase }

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
	rec.Ecosystem = osv.EcosystemOSSFuzz
	return &rec, nil
}

// ============================================================
// Root
// ============================================================

type RecordRoot struct {
	osv.Record
	Affected         []AffectedRoot `json:"affected,omitempty"`
	DatabaseSpecific TopRoot        `json:"database_specific,omitzero"`
}

func (r *RecordRoot) Base() *osv.Record  { return &r.Record }
func (r *RecordRoot) AffectedAny() []any { return affectedAny(r.Affected) }

type AffectedRoot struct {
	osv.AffectedBase
	Ranges            []RangeRoot     `json:"ranges,omitempty"`
	EcosystemSpecific AffectedEcoRoot `json:"ecosystem_specific,omitzero"`
	DatabaseSpecific  AffectedDBRoot  `json:"database_specific,omitzero"`
}

type RangeRoot struct{ osv.RangeBase }

type TopRoot struct {
	// All Root fields round-trip with their bare presence even when
	// empty (e.g. distro_version = "" on gobinary advisories), so
	// none of them get omitempty.
	Distro        string `json:"distro"`
	DistroVersion string `json:"distro_version"`
	Severity      string `json:"severity,omitempty"`
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
	rec.Ecosystem = osv.EcosystemRoot
	return &rec, nil
}

// ============================================================
// npm
// ============================================================

type RecordNpm struct {
	osv.Record
	Affected         []AffectedNpm `json:"affected,omitempty"`
	DatabaseSpecific TopNpm        `json:"database_specific,omitzero"`
}

func (r *RecordNpm) Base() *osv.Record  { return &r.Record }
func (r *RecordNpm) AffectedAny() []any { return affectedAny(r.Affected) }

type AffectedNpm struct {
	osv.AffectedBase
	Ranges            []RangeNpm     `json:"ranges,omitempty"`
	EcosystemSpecific AffectedEcoNpm `json:"ecosystem_specific,omitzero"`
	DatabaseSpecific  AffectedDBNpm  `json:"database_specific,omitzero"`
}

type RangeNpm struct{ osv.RangeBase }

type TopNpm struct {
	CAPECIDs                 []string               `json:"capec_ids,omitempty"`
	CPEIDs                   []string               `json:"cpe_ids,omitempty"`
	CWEIDs                   []string               `json:"cwe_ids"`
	GitHubReviewed           bool                   `json:"github_reviewed,omitempty"`
	GitHubReviewedAt         time.Time              `json:"github_reviewed_at,omitzero"`
	IOCs                     *NpmIOCs               `json:"iocs,omitempty"`
	MaliciousPackagesOrigins []NpmMalPackagesOrigin `json:"malicious-packages-origins,omitempty"`
	NVDPublishedAt           time.Time              `json:"nvd_published_at,omitzero"`
	Severity                 string                 `json:"severity,omitempty"`
}

func (t TopNpm) IsZero() bool {
	return t.CAPECIDs == nil && t.CPEIDs == nil &&
		t.CWEIDs == nil && !t.GitHubReviewed && t.GitHubReviewedAt.IsZero() &&
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
	Events []osv.Event `json:"events,omitempty"`
	Repo   string      `json:"repo,omitempty"`
	Type   string      `json:"type,omitempty"`
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
	rec.Ecosystem = osv.EcosystemNpm
	return &rec, nil
}
