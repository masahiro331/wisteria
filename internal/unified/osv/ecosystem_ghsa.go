package osv

import (
	"encoding/json"
	"fmt"
	"time"
)

// ghsa-derived ecosystems share the same database_specific shape because
// they all originate from github.com/github/advisory-database. We still
// declare one struct per ecosystem (not a shared `TopGHSA`) because the
// design's strict-dispatch rule keeps each ecosystem's schema
// independent: if Maven later ships a key Hex never sees, the divergence
// can land in TopMaven without rippling.

// --- Maven --------------------------------------------------------

type TopMaven struct {
	CWEIDs                   []string                `json:"cwe_ids"`
	GitHubReviewed           bool                    `json:"github_reviewed,omitempty"`
	GitHubReviewedAt         time.Time               `json:"github_reviewed_at,omitzero"`
	MaliciousPackagesOrigins []GHSAMalPackagesOrigin `json:"malicious-packages-origins,omitempty"`
	NVDPublishedAt           time.Time               `json:"nvd_published_at,omitzero"`
	Severity                 string                  `json:"severity,omitempty"`
}

func (*TopMaven) isTopSpecific() {}

type AffectedEcoMaven struct{}

func (*AffectedEcoMaven) isAffectedEcoSpec() {}

// AffectedDBMaven holds the GHSA importer's per-affected metadata.
// CVSS is the malicious-packages variant (object form `{score,
// vectorString}`); the rare upstream string form is supported via
// MavenCVSS's custom JSON. CVSS is a pointer so an absent upstream key
// round-trips as absent rather than as `null`.
type AffectedDBMaven struct {
	CVSS                          *MavenCVSS `json:"cvss,omitempty"`
	CWEs                          []GHSACWE  `json:"cwes,omitempty"`
	GHSA                          string     `json:"ghsa,omitempty"`
	LastKnownAffectedVersionRange string     `json:"last_known_affected_version_range,omitempty"`
	Source                        string     `json:"source,omitempty"`
}

// MavenCVSS round-trips both observed shapes for Maven's per-affected
// `cvss` field: the object form `{score, vectorString}` (used by
// malicious-packages imports) and a bare CVSS vector string (older
// GHSA shape).
type MavenCVSS struct {
	Set          bool
	Score        float64
	VectorString *string
	Vector       string
}

func (c MavenCVSS) MarshalJSON() ([]byte, error) {
	if !c.Set {
		return []byte("null"), nil
	}
	if c.Vector != "" {
		return json.Marshal(c.Vector)
	}
	type tmp struct {
		Score        float64 `json:"score"`
		VectorString *string `json:"vectorString"`
	}
	return json.Marshal(tmp{Score: c.Score, VectorString: c.VectorString})
}

func (c *MavenCVSS) UnmarshalJSON(b []byte) error {
	if len(b) == 0 || string(b) == "null" {
		*c = MavenCVSS{}
		return nil
	}
	switch b[0] {
	case '"':
		var v string
		if err := json.Unmarshal(b, &v); err != nil {
			return err
		}
		*c = MavenCVSS{Set: true, Vector: v}
		return nil
	case '{':
		var t struct {
			Score        float64 `json:"score"`
			VectorString *string `json:"vectorString"`
		}
		if err := json.Unmarshal(b, &t); err != nil {
			return err
		}
		*c = MavenCVSS{Set: true, Score: t.Score, VectorString: t.VectorString}
		return nil
	default:
		return fmt.Errorf("MavenCVSS: unexpected JSON %q", b)
	}
}

func (*AffectedDBMaven) isAffectedDBSpec() {}

type RangeDBMaven struct{}

func (*RangeDBMaven) isRangeDBSpec() {}

// --- Hex ---------------------------------------------------------

type TopHex struct {
	CAPECIDs         []string  `json:"capec_ids,omitempty"`
	CPEIDs           []string  `json:"cpe_ids,omitempty"`
	CWEIDs           []string  `json:"cwe_ids"`
	GitHubReviewed   bool      `json:"github_reviewed,omitempty"`
	GitHubReviewedAt time.Time `json:"github_reviewed_at,omitzero"`
	NVDPublishedAt   time.Time `json:"nvd_published_at,omitzero"`
	Severity         string    `json:"severity,omitempty"`
}

func (*TopHex) isTopSpecific() {}

type AffectedEcoHex struct{}

func (*AffectedEcoHex) isAffectedEcoSpec() {}

type AffectedDBHex struct {
	LastKnownAffectedVersionRange string `json:"last_known_affected_version_range,omitempty"`
	Source                        string `json:"source,omitempty"`
}

func (*AffectedDBHex) isAffectedDBSpec() {}

type RangeDBHex struct{}

func (*RangeDBHex) isRangeDBSpec() {}

// --- NuGet -------------------------------------------------------

type TopNuGet struct {
	CWEIDs                   []string                `json:"cwe_ids"`
	GitHubReviewed           bool                    `json:"github_reviewed,omitempty"`
	GitHubReviewedAt         time.Time               `json:"github_reviewed_at,omitzero"`
	MaliciousPackagesOrigins []GHSAMalPackagesOrigin `json:"malicious-packages-origins,omitempty"`
	NVDPublishedAt           time.Time               `json:"nvd_published_at,omitzero"`
	Severity                 string                  `json:"severity,omitempty"`
}

func (*TopNuGet) isTopSpecific() {}

type AffectedEcoNuGet struct{}

func (*AffectedEcoNuGet) isAffectedEcoSpec() {}

type AffectedDBNuGet struct {
	LastKnownAffectedVersionRange string `json:"last_known_affected_version_range,omitempty"`
	Source                        string `json:"source,omitempty"`
}

func (*AffectedDBNuGet) isAffectedDBSpec() {}

type RangeDBNuGet struct{}

func (*RangeDBNuGet) isRangeDBSpec() {}

// --- RubyGems ----------------------------------------------------

type TopRubyGems struct {
	CWEIDs                   []string                `json:"cwe_ids"`
	GitHubReviewed           bool                    `json:"github_reviewed,omitempty"`
	GitHubReviewedAt         time.Time               `json:"github_reviewed_at,omitzero"`
	MaliciousPackagesOrigins []GHSAMalPackagesOrigin `json:"malicious-packages-origins,omitempty"`
	NVDPublishedAt           time.Time               `json:"nvd_published_at,omitzero"`
	Severity                 string                  `json:"severity,omitempty"`
}

func (*TopRubyGems) isTopSpecific() {}

type AffectedEcoRubyGems struct{}

func (*AffectedEcoRubyGems) isAffectedEcoSpec() {}

type AffectedDBRubyGems struct {
	LastKnownAffectedVersionRange string `json:"last_known_affected_version_range,omitempty"`
	Source                        string `json:"source,omitempty"`
}

func (*AffectedDBRubyGems) isAffectedDBSpec() {}

type RangeDBRubyGems struct{}

func (*RangeDBRubyGems) isRangeDBSpec() {}

// --- Pub ---------------------------------------------------------

type TopPub struct {
	CWEIDs           []string  `json:"cwe_ids"`
	GitHubReviewed   bool      `json:"github_reviewed,omitempty"`
	GitHubReviewedAt time.Time `json:"github_reviewed_at,omitzero"`
	NVDPublishedAt   time.Time `json:"nvd_published_at,omitzero"`
	Severity         string    `json:"severity,omitempty"`
}

func (*TopPub) isTopSpecific() {}

type AffectedEcoPub struct{}

func (*AffectedEcoPub) isAffectedEcoSpec() {}

type AffectedDBPub struct {
	LastKnownAffectedVersionRange string `json:"last_known_affected_version_range,omitempty"`
	Source                        string `json:"source,omitempty"`
}

func (*AffectedDBPub) isAffectedDBSpec() {}

type RangeDBPub struct{}

func (*RangeDBPub) isRangeDBSpec() {}

// --- SwiftURL ----------------------------------------------------

type TopSwiftURL struct {
	CWEIDs           []string  `json:"cwe_ids"`
	GitHubReviewed   bool      `json:"github_reviewed,omitempty"`
	GitHubReviewedAt time.Time `json:"github_reviewed_at,omitzero"`
	NVDPublishedAt   time.Time `json:"nvd_published_at,omitzero"`
	Severity         string    `json:"severity,omitempty"`
}

func (*TopSwiftURL) isTopSpecific() {}

type AffectedEcoSwiftURL struct{}

func (*AffectedEcoSwiftURL) isAffectedEcoSpec() {}

type AffectedDBSwiftURL struct {
	LastKnownAffectedVersionRange string `json:"last_known_affected_version_range,omitempty"`
	Source                        string `json:"source,omitempty"`
}

func (*AffectedDBSwiftURL) isAffectedDBSpec() {}

type RangeDBSwiftURL struct{}

func (*RangeDBSwiftURL) isRangeDBSpec() {}

// --- GitHub Actions ----------------------------------------------

type TopGitHubActions struct {
	CWEIDs           []string  `json:"cwe_ids"`
	GitHubReviewed   bool      `json:"github_reviewed,omitempty"`
	GitHubReviewedAt time.Time `json:"github_reviewed_at,omitzero"`
	NVDPublishedAt   time.Time `json:"nvd_published_at,omitzero"`
	Severity         string    `json:"severity,omitempty"`
}

func (*TopGitHubActions) isTopSpecific() {}

type AffectedEcoGitHubActions struct{}

func (*AffectedEcoGitHubActions) isAffectedEcoSpec() {}

type AffectedDBGitHubActions struct {
	LastKnownAffectedVersionRange string `json:"last_known_affected_version_range,omitempty"`
	Source                        string `json:"source,omitempty"`
}

func (*AffectedDBGitHubActions) isAffectedDBSpec() {}

type RangeDBGitHubActions struct{}

func (*RangeDBGitHubActions) isRangeDBSpec() {}

// --- Packagist ---------------------------------------------------

type TopPackagist struct {
	CWEIDs           []string  `json:"cwe_ids"`
	GitHubReviewed   bool      `json:"github_reviewed,omitempty"`
	GitHubReviewedAt time.Time `json:"github_reviewed_at,omitzero"`
	NVDPublishedAt   time.Time `json:"nvd_published_at,omitzero"`
	Severity         string    `json:"severity,omitempty"`
}

func (*TopPackagist) isTopSpecific() {}

type AffectedEcoPackagist struct{}

func (*AffectedEcoPackagist) isAffectedEcoSpec() {}

type AffectedDBPackagist struct {
	AffectedVersions              string `json:"affected_versions,omitempty"`
	LastKnownAffectedVersionRange string `json:"last_known_affected_version_range,omitempty"`
	Patched                       bool   `json:"patched,omitempty"`
	Source                        string `json:"source,omitempty"`
}

func (*AffectedDBPackagist) isAffectedDBSpec() {}

type RangeDBPackagist struct {
	Constraint string `json:"constraint,omitempty"`
}

func (*RangeDBPackagist) isRangeDBSpec() {}

// --- crates.io ---------------------------------------------------

type TopCratesIO struct {
	CWEIDs                   []string                `json:"cwe_ids"`
	GitHubReviewed           bool                    `json:"github_reviewed,omitempty"`
	GitHubReviewedAt         time.Time               `json:"github_reviewed_at,omitzero"`
	License                  string                  `json:"license,omitempty"`
	MaliciousPackagesOrigins []GHSAMalPackagesOrigin `json:"malicious-packages-origins,omitempty"`
	NVDPublishedAt           time.Time               `json:"nvd_published_at,omitzero"`
	Severity                 string                  `json:"severity,omitempty"`
}

func (*TopCratesIO) isTopSpecific() {}

type AffectedEcoCratesIO struct {
	AffectedFunctions []string         `json:"affected_functions"`
	Affects           *CratesIOAffects `json:"affects,omitempty"`
}

func (*AffectedEcoCratesIO) isAffectedEcoSpec() {}

type CratesIOAffects struct {
	Arch      []string `json:"arch"`
	Functions []string `json:"functions"`
	OS        []string `json:"os"`
}

type AffectedDBCratesIO struct {
	Categories                    []string   `json:"categories,omitempty"`
	CVSS                          *MavenCVSS `json:"cvss,omitempty"`
	CWEs                          []GHSACWE  `json:"cwes,omitempty"`
	Informational                 *string    `json:"informational"`
	LastKnownAffectedVersionRange string     `json:"last_known_affected_version_range,omitempty"`
	Source                        string     `json:"source,omitempty"`
}

func (*AffectedDBCratesIO) isAffectedDBSpec() {}

type RangeDBCratesIO struct{}

func (*RangeDBCratesIO) isRangeDBSpec() {}

// --- shared GHSA helper structs (used by multiple ecosystems above) --

// GHSAMalPackagesOrigin captures the malicious-packages provenance
// records the GHSA importer attaches to npm/Maven/PyPI/RubyGems/etc.
type GHSAMalPackagesOrigin struct {
	ID           string                 `json:"id,omitempty"`
	ImportTime   time.Time              `json:"import_time,omitzero"`
	ModifiedTime time.Time              `json:"modified_time,omitzero"`
	Ranges       []PyPIMalPackagesRange `json:"ranges,omitempty"`
	SHA256       string                 `json:"sha256,omitempty"`
	Source       string                 `json:"source,omitempty"`
	Versions     []string               `json:"versions,omitempty"`
}

// GHSACWE is the CWE detail GHSA attaches to malicious-package
// affected.database_specific entries.
type GHSACWE struct {
	CWEID       string `json:"cweId,omitempty"`
	Description string `json:"description,omitempty"`
	Name        string `json:"name,omitempty"`
}

func init() {
	register("Maven", ecosystemDispatch{
		top:    func() TopSpecific { return &TopMaven{} },
		affEco: func() AffectedEcoSpec { return &AffectedEcoMaven{} },
		affDB:  func() AffectedDBSpec { return &AffectedDBMaven{} },
		rngDB:  func() RangeDBSpec { return &RangeDBMaven{} },
	})
	register("Hex", ecosystemDispatch{
		top:    func() TopSpecific { return &TopHex{} },
		affEco: func() AffectedEcoSpec { return &AffectedEcoHex{} },
		affDB:  func() AffectedDBSpec { return &AffectedDBHex{} },
		rngDB:  func() RangeDBSpec { return &RangeDBHex{} },
	})
	register("NuGet", ecosystemDispatch{
		top:    func() TopSpecific { return &TopNuGet{} },
		affEco: func() AffectedEcoSpec { return &AffectedEcoNuGet{} },
		affDB:  func() AffectedDBSpec { return &AffectedDBNuGet{} },
		rngDB:  func() RangeDBSpec { return &RangeDBNuGet{} },
	})
	register("RubyGems", ecosystemDispatch{
		top:    func() TopSpecific { return &TopRubyGems{} },
		affEco: func() AffectedEcoSpec { return &AffectedEcoRubyGems{} },
		affDB:  func() AffectedDBSpec { return &AffectedDBRubyGems{} },
		rngDB:  func() RangeDBSpec { return &RangeDBRubyGems{} },
	})
	register("Pub", ecosystemDispatch{
		top:    func() TopSpecific { return &TopPub{} },
		affEco: func() AffectedEcoSpec { return &AffectedEcoPub{} },
		affDB:  func() AffectedDBSpec { return &AffectedDBPub{} },
		rngDB:  func() RangeDBSpec { return &RangeDBPub{} },
	})
	register("SwiftURL", ecosystemDispatch{
		top:    func() TopSpecific { return &TopSwiftURL{} },
		affEco: func() AffectedEcoSpec { return &AffectedEcoSwiftURL{} },
		affDB:  func() AffectedDBSpec { return &AffectedDBSwiftURL{} },
		rngDB:  func() RangeDBSpec { return &RangeDBSwiftURL{} },
	})
	register("GitHub Actions", ecosystemDispatch{
		top:    func() TopSpecific { return &TopGitHubActions{} },
		affEco: func() AffectedEcoSpec { return &AffectedEcoGitHubActions{} },
		affDB:  func() AffectedDBSpec { return &AffectedDBGitHubActions{} },
		rngDB:  func() RangeDBSpec { return &RangeDBGitHubActions{} },
	})
	register("Packagist", ecosystemDispatch{
		top:    func() TopSpecific { return &TopPackagist{} },
		affEco: func() AffectedEcoSpec { return &AffectedEcoPackagist{} },
		affDB:  func() AffectedDBSpec { return &AffectedDBPackagist{} },
		rngDB:  func() RangeDBSpec { return &RangeDBPackagist{} },
	})
	register("crates.io", ecosystemDispatch{
		top:    func() TopSpecific { return &TopCratesIO{} },
		affEco: func() AffectedEcoSpec { return &AffectedEcoCratesIO{} },
		affDB:  func() AffectedDBSpec { return &AffectedDBCratesIO{} },
		rngDB:  func() RangeDBSpec { return &RangeDBCratesIO{} },
	})
}
