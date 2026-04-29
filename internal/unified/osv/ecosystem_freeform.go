package osv

import (
	"encoding/json"
	"fmt"
	"time"
)

// Ecosystems whose database_specific blob carries a free-form
// CVE-style metadata payload (Generic, GIT) plus the remaining
// straggler ecosystems (Go, OSS-Fuzz, Root, npm).

// --- Generic ------------------------------------------------------

// Generic is the OSV bucket for advisories without an obvious
// ecosystem (typically osv-cve-conversion output). The
// database_specific block is a CVE-derived payload — most fields are
// optional and a handful (severity in particular) round-trip as null.

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
	Severity         GenericSeverity `json:"severity,omitempty"`
	WWW              string          `json:"www,omitempty"`
}

func (*TopGeneric) isTopSpecific() {}

type GenericCWE struct {
	Desc string `json:"desc,omitempty"`
	ID   string `json:"id,omitempty"`
}

type GenericAward struct {
	Amount   string `json:"amount,omitempty"`
	Currency string `json:"currency,omitempty"`
}

// GenericSeverity round-trips both string ("Medium") and null variants
// observed in the upstream Generic bucket. Empty struct → null.
type GenericSeverity struct {
	Set   bool
	Label string
}

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

func (*AffectedEcoGeneric) isAffectedEcoSpec() {}

type AffectedDBGeneric struct {
	Source             string                   `json:"source,omitempty"`
	UnresolvedRanges   []UnresolvedRange        `json:"unresolved_ranges,omitempty"`
	UnresolvedVersions []UnresolvedVersionRange `json:"unresolved_versions,omitempty"`
}

func (*AffectedDBGeneric) isAffectedDBSpec() {}

// UnresolvedRange is the shape upstream uses for `unresolved_ranges` —
// no `type` field (the importer never emits one), just an `events`
// list. Used by Generic / GIT.
type UnresolvedRange struct {
	Events []Event `json:"events,omitempty"`
}

// UnresolvedVersionRange is the shape upstream uses for
// `unresolved_versions` — same as UnresolvedRange but with a `type`
// field that round-trips even when empty (Generic emits `"type": ""`
// for unmappable Go module versions).
type UnresolvedVersionRange struct {
	Events []Event `json:"events,omitempty"`
	Type   string  `json:"type"`
}

type RangeDBGeneric struct{}

func (*RangeDBGeneric) isRangeDBSpec() {}

// --- GIT ----------------------------------------------------------

// GIT is the OSV bucket for git-only advisories (typically derived
// from CVE conversion). Inventory: top has 19 keys, affEco has
// fixed_range/introduced_range/opam_constraint/severity/urgency,
// affDB carries vanir signatures, range carries cpe/extracted_events
// /source/versions.

type TopGIT struct {
	CWE                      *GenericCWE             `json:"CWE,omitempty"`
	URL                      string                  `json:"URL,omitempty"`
	Affects                  string                  `json:"affects,omitempty"`
	Award                    *GenericAward           `json:"award,omitempty"`
	CAPECIDs                 []string                `json:"capec_ids,omitempty"`
	CNAAssigner              string                  `json:"cna_assigner,omitempty"`
	CPEIDs                   []string                `json:"cpe_ids,omitempty"`
	Cwe                      []string                `json:"cwe,omitempty"`
	CWEIDs                   []string                `json:"cwe_ids,omitempty"`
	HumanLink                string                  `json:"human_link,omitempty"`
	Issue                    string                  `json:"issue,omitempty"`
	LastAffected             string                  `json:"last_affected,omitempty"`
	MaliciousPackagesOrigins []GHSAMalPackagesOrigin `json:"malicious-packages-origins,omitempty"`
	OSV                      string                  `json:"osv,omitempty"`
	OSVGeneratedFrom         string                  `json:"osv_generated_from,omitempty"`
	Package                  string                  `json:"package,omitempty"`
	Severity                 GenericSeverity         `json:"severity,omitempty"`
	UnresolvedRanges         []GITUnresolvedRange    `json:"unresolved_ranges,omitempty"`
	WWW                      string                  `json:"www,omitempty"`
}

func (*TopGIT) isTopSpecific() {}

// GITUnresolvedRange is the per-CPE block GIT attaches to records the
// importer could not normalise into a Range — same shape as
// RangeDBGIT plus an optional events list (the latter only appears on
// the affected-level unresolved_ranges, not the top-level one).
type GITUnresolvedRange struct {
	CPE             string  `json:"cpe,omitempty"`
	Events          []Event `json:"events,omitempty"`
	ExtractedEvents []Event `json:"extracted_events,omitempty"`
	Source          string  `json:"source,omitempty"`
}

// AffectedEcoGIT covers a wide grab-bag observed across CVE-converted
// records that landed in the GIT bucket.
type AffectedEcoGIT struct {
	FixedRange      string          `json:"fixed_range,omitempty"`
	IntroducedRange string          `json:"introduced_range,omitempty"`
	OpamConstraint  string          `json:"opam_constraint,omitempty"`
	Severity        GenericSeverity `json:"severity,omitempty"`
	Urgency         string          `json:"urgency,omitempty"`
}

func (*AffectedEcoGIT) isAffectedEcoSpec() {}

type AffectedDBGIT struct {
	FixedRange              string                  `json:"fixed_range,omitempty"`
	IntroducedRange         string                  `json:"introduced_range,omitempty"`
	Source                  string                  `json:"source,omitempty"`
	UnresolvedRanges        []GITUnresolvedRange    `json:"unresolved_ranges,omitempty"`
	VanirSignatures         []AndroidVanirSignature `json:"vanir_signatures,omitempty"`
	VanirSignaturesModified time.Time               `json:"vanir_signatures_modified,omitzero"`
}

func (*AffectedDBGIT) isAffectedDBSpec() {}

type RangeDBGIT struct {
	CPE             GITRangeCPE `json:"cpe,omitempty"`
	ExtractedEvents []Event     `json:"extracted_events,omitempty"`
	Source          string      `json:"source,omitempty"`
	Versions        []Event     `json:"versions,omitempty"`
}

// GITRangeCPE round-trips both string and []string variants found
// upstream — most records emit a bare string, but advisories that
// match multiple CPEs ship an array.
type GITRangeCPE struct {
	Set    bool
	Single string
	Multi  []string
}

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

func (*RangeDBGIT) isRangeDBSpec() {}

// --- Go -----------------------------------------------------------

type TopGo struct {
	CWEIDs                   []string                `json:"cwe_ids,omitempty"`
	GitHubReviewed           bool                    `json:"github_reviewed,omitempty"`
	GitHubReviewedAt         time.Time               `json:"github_reviewed_at,omitzero"`
	MaliciousPackagesOrigins []GHSAMalPackagesOrigin `json:"malicious-packages-origins,omitempty"`
	NVDPublishedAt           time.Time               `json:"nvd_published_at,omitzero"`
	ReviewStatus             string                  `json:"review_status,omitempty"`
	Severity                 string                  `json:"severity,omitempty"`
	URL                      string                  `json:"url,omitempty"`
}

func (*TopGo) isTopSpecific() {}

type AffectedEcoGo struct {
	CustomRanges []GoCustomRange `json:"custom_ranges,omitempty"`
	GOOS         []string        `json:"goos,omitempty"`
	Imports      []GoImport      `json:"imports,omitempty"`
	Severity     string          `json:"severity,omitempty"`
	Symbols      []string        `json:"symbols,omitempty"`
}

func (*AffectedEcoGo) isAffectedEcoSpec() {}

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

func (*AffectedDBGo) isAffectedDBSpec() {}

type RangeDBGo struct{}

func (*RangeDBGo) isRangeDBSpec() {}

// --- OSS-Fuzz -----------------------------------------------------

type TopOSSFuzz struct{}

func (*TopOSSFuzz) isTopSpecific() {}

type AffectedEcoOSSFuzz struct {
	FixedRange      string          `json:"fixed_range,omitempty"`
	IntroducedRange string          `json:"introduced_range,omitempty"`
	Severity        GenericSeverity `json:"severity,omitempty"`
}

func (*AffectedEcoOSSFuzz) isAffectedEcoSpec() {}

type AffectedDBOSSFuzz struct {
	FixedRange      string `json:"fixed_range,omitempty"`
	IntroducedRange string `json:"introduced_range,omitempty"`
	Source          string `json:"source,omitempty"`
}

func (*AffectedDBOSSFuzz) isAffectedDBSpec() {}

type RangeDBOSSFuzz struct{}

func (*RangeDBOSSFuzz) isRangeDBSpec() {}

// --- Root ---------------------------------------------------------

type TopRoot struct {
	// distro_version round-trips as "" for some Root advisories so we
	// drop omitempty here — the raw upstream key is always present.
	Distro        string `json:"distro"`
	DistroVersion string `json:"distro_version"`
	Source        string `json:"source"`
}

func (*TopRoot) isTopSpecific() {}

type AffectedEcoRoot struct{}

func (*AffectedEcoRoot) isAffectedEcoSpec() {}

type AffectedDBRoot struct {
	// All Root fields round-trip with their bare presence even when
	// empty (e.g. root_patch_version = "" on gobinary advisories), so
	// none of them get omitempty.
	AllFixedVersions   []string `json:"all_fixed_versions"`
	RootPatchVersion   string   `json:"root_patch_version"`
	RootPatched        bool     `json:"root_patched"`
	Source             string   `json:"source"`
	TotalFixedVersions int      `json:"total_fixed_versions"`
	UpstreamVersion    string   `json:"upstream_version"`
}

func (*AffectedDBRoot) isAffectedDBSpec() {}

type RangeDBRoot struct{}

func (*RangeDBRoot) isRangeDBSpec() {}

// --- npm ----------------------------------------------------------

type TopNpm struct {
	CWEIDs                   []string                `json:"cwe_ids"`
	GitHubReviewed           bool                    `json:"github_reviewed,omitempty"`
	GitHubReviewedAt         time.Time               `json:"github_reviewed_at,omitzero"`
	IOCs                     *PyPIIOCs               `json:"iocs,omitempty"`
	MaliciousPackagesOrigins []GHSAMalPackagesOrigin `json:"malicious-packages-origins,omitempty"`
	NVDPublishedAt           time.Time               `json:"nvd_published_at,omitzero"`
	Severity                 string                  `json:"severity,omitempty"`
}

func (*TopNpm) isTopSpecific() {}

type AffectedEcoNpm struct{}

func (*AffectedEcoNpm) isAffectedEcoSpec() {}

type AffectedDBNpm struct {
	CVSS                          *NpmCVSS  `json:"cvss,omitempty"`
	CWEs                          []GHSACWE `json:"cwes"`
	GHSA                          string    `json:"ghsa,omitempty"`
	LastKnownAffectedVersionRange string    `json:"last_known_affected_version_range,omitempty"`
	Source                        string    `json:"source,omitempty"`
}

func (*AffectedDBNpm) isAffectedDBSpec() {}

// NpmCVSS holds the GHSA-attached score block. VectorString round-trips
// as null for entries that did not carry a vector, hence the pointer.
type NpmCVSS struct {
	Score        float64 `json:"score"`
	VectorString *string `json:"vectorString"`
}

type RangeDBNpm struct{}

func (*RangeDBNpm) isRangeDBSpec() {}

func init() {
	register("Generic", ecosystemDispatch{
		top:    func() TopSpecific { return &TopGeneric{} },
		affEco: func() AffectedEcoSpec { return &AffectedEcoGeneric{} },
		affDB:  func() AffectedDBSpec { return &AffectedDBGeneric{} },
		rngDB:  func() RangeDBSpec { return &RangeDBGeneric{} },
	})
	register("GIT", ecosystemDispatch{
		top:    func() TopSpecific { return &TopGIT{} },
		affEco: func() AffectedEcoSpec { return &AffectedEcoGIT{} },
		affDB:  func() AffectedDBSpec { return &AffectedDBGIT{} },
		rngDB:  func() RangeDBSpec { return &RangeDBGIT{} },
	})
	register("Go", ecosystemDispatch{
		top:    func() TopSpecific { return &TopGo{} },
		affEco: func() AffectedEcoSpec { return &AffectedEcoGo{} },
		affDB:  func() AffectedDBSpec { return &AffectedDBGo{} },
		rngDB:  func() RangeDBSpec { return &RangeDBGo{} },
	})
	register("OSS-Fuzz", ecosystemDispatch{
		top:    func() TopSpecific { return &TopOSSFuzz{} },
		affEco: func() AffectedEcoSpec { return &AffectedEcoOSSFuzz{} },
		affDB:  func() AffectedDBSpec { return &AffectedDBOSSFuzz{} },
		rngDB:  func() RangeDBSpec { return &RangeDBOSSFuzz{} },
	})
	register("Root", ecosystemDispatch{
		top:    func() TopSpecific { return &TopRoot{} },
		affEco: func() AffectedEcoSpec { return &AffectedEcoRoot{} },
		affDB:  func() AffectedDBSpec { return &AffectedDBRoot{} },
		rngDB:  func() RangeDBSpec { return &RangeDBRoot{} },
	})
	register("npm", ecosystemDispatch{
		top:    func() TopSpecific { return &TopNpm{} },
		affEco: func() AffectedEcoSpec { return &AffectedEcoNpm{} },
		affDB:  func() AffectedDBSpec { return &AffectedDBNpm{} },
		rngDB:  func() RangeDBSpec { return &RangeDBNpm{} },
	})
}
