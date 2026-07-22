package ecosystem

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/masahiro331/wisteria/internal/unified/osv"
)

// RecordMaven is one OSV advisory from the Maven ecosystem (typically
// GHSA-imported).

type RecordMaven struct {
	osv.Record
	Affected         []AffectedMaven `json:"affected,omitempty"`
	DatabaseSpecific TopMaven        `json:"database_specific,omitzero"`
}

func (r *RecordMaven) Base() *osv.Record  { return &r.Record }
func (r *RecordMaven) AffectedAny() []any { return affectedAny(r.Affected) }
func (r *RecordMaven) CWEIDs() []string   { return r.DatabaseSpecific.CWEIDs }

type AffectedMaven struct {
	osv.AffectedBase
	Ranges            []RangeMaven     `json:"ranges,omitempty"`
	EcosystemSpecific AffectedEcoMaven `json:"ecosystem_specific,omitzero"`
	DatabaseSpecific  AffectedDBMaven  `json:"database_specific,omitzero"`
}

type RangeMaven struct{ osv.RangeBase }

// TopMaven keeps `cwe_ids` non-omitempty because GHSA emits an empty
// array for advisories with no CWE assigned, and the round-trip
// verifier requires the bare presence to survive.
type TopMaven struct {
	CWEIDs                   []string                 `json:"cwe_ids"`
	GitHubReviewed           bool                     `json:"github_reviewed,omitempty"`
	GitHubReviewedAt         time.Time                `json:"github_reviewed_at,omitzero"`
	MaliciousPackagesOrigins []MavenMalPackagesOrigin `json:"malicious-packages-origins,omitempty"`
	NVDPublishedAt           time.Time                `json:"nvd_published_at,omitzero"`
	Severity                 string                   `json:"severity,omitempty"`
}

func (t TopMaven) IsZero() bool {
	return t.CWEIDs == nil && !t.GitHubReviewed && t.GitHubReviewedAt.IsZero() &&
		t.MaliciousPackagesOrigins == nil && t.NVDPublishedAt.IsZero() && t.Severity == ""
}

// MavenMalPackagesOrigin captures the malicious-packages provenance
// records the GHSA importer attaches.
type MavenMalPackagesOrigin struct {
	ID           string                  `json:"id,omitempty"`
	ImportTime   time.Time               `json:"import_time,omitzero"`
	ModifiedTime time.Time               `json:"modified_time,omitzero"`
	Ranges       []MavenMalPackagesRange `json:"ranges,omitempty"`
	SHA256       string                  `json:"sha256,omitempty"`
	Source       string                  `json:"source,omitempty"`
	Versions     []string                `json:"versions,omitempty"`
}

type MavenMalPackagesRange struct {
	Events []osv.Event `json:"events,omitempty"`
	Repo   string      `json:"repo,omitempty"`
	Type   string      `json:"type,omitempty"`
}

type AffectedEcoMaven struct{}

func (AffectedEcoMaven) IsZero() bool { return true }

// AffectedDBMaven holds the GHSA importer's per-affected metadata.
// CVSS is the malicious-packages variant (object form `{score,
// vectorString}`); the rare upstream string form is supported via
// MavenCVSS's custom JSON. CVSS is a pointer so an absent upstream
// key round-trips as absent rather than as `null`.
type AffectedDBMaven struct {
	CVSS                          *MavenCVSS `json:"cvss,omitempty"`
	CWEs                          []MavenCWE `json:"cwes,omitempty"`
	GHSA                          string     `json:"ghsa,omitempty"`
	LastKnownAffectedVersionRange string     `json:"last_known_affected_version_range,omitempty"`
	Source                        string     `json:"source,omitempty"`
}

func (a AffectedDBMaven) IsZero() bool {
	return a.CVSS == nil && a.CWEs == nil && a.GHSA == "" &&
		a.LastKnownAffectedVersionRange == "" && a.Source == ""
}

// MavenCVSS round-trips both observed shapes for Maven's per-affected
// `cvss` field: the object form `{score, vectorString}` (used by
// malicious-packages imports) and a bare CVSS vector string (older
// GHSA shape).
type MavenCVSS struct {
	Score        float64 `json:"score"`
	VectorString *string `json:"vectorString"`
	// Vector is set when upstream emitted a bare CVSS string; in that
	// case Score / VectorString stay zero and MarshalJSON re-emits
	// just the string form.
	Vector string `json:"-"`
}

func (c MavenCVSS) MarshalJSON() ([]byte, error) {
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
		*c = MavenCVSS{Vector: v}
		return nil
	case '{':
		var t struct {
			Score        float64 `json:"score"`
			VectorString *string `json:"vectorString"`
		}
		if err := json.Unmarshal(b, &t); err != nil {
			return err
		}
		*c = MavenCVSS{Score: t.Score, VectorString: t.VectorString}
		return nil
	default:
		return fmt.Errorf("MavenCVSS: unexpected JSON %q", b)
	}
}

type MavenCWE struct {
	CWEID       string `json:"cweId,omitempty"`
	Description string `json:"description,omitempty"`
	Name        string `json:"name,omitempty"`
}

func NewRecordMaven(r io.Reader) (*RecordMaven, error) {
	var rec RecordMaven
	if err := json.NewDecoder(r).Decode(&rec); err != nil {
		return nil, fmt.Errorf("osv: parse Maven: %w", err)
	}
	rec.Ecosystem = osv.EcosystemMaven
	return &rec, nil
}
