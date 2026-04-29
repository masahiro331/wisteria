package osv

import (
	"encoding/json"
	"fmt"
	"time"
)

// PyPI is the OSV.dev "PyPI" upstream ecosystem. The shapes below are
// the union of every key observed under tmp/sources/osv/PyPI/ — see
// tools/osv-inventory for how the inventory is regenerated.

// TopPyPI is `database_specific` at the record root for PyPI advisories.
//
// The malicious-packages-origins / iocs blobs only appear on entries
// converted from the OSSF malicious-packages feed; for normal GHSA
// imports those fields are absent and the GHSA review metadata
// (cwe_ids, github_reviewed, ...) is what's populated. One struct
// covers both populations.
type TopPyPI struct {
	CWEIDs                   []string                `json:"cwe_ids,omitempty"`
	GitHubReviewed           bool                    `json:"github_reviewed,omitempty"`
	GitHubReviewedAt         time.Time               `json:"github_reviewed_at,omitzero"`
	IOCs                     *PyPIIOCs               `json:"iocs,omitempty"`
	MaliciousPackagesOrigins []PyPIMalPackagesOrigin `json:"malicious-packages-origins,omitempty"`
	NVDPublishedAt           time.Time               `json:"nvd_published_at,omitzero"`
	Severity                 string                  `json:"severity,omitempty"`
}

func (*TopPyPI) isTopSpecific() {}

// PyPIIOCs holds indicator-of-compromise data for malicious-package
// reports in the PyPI feed.
type PyPIIOCs struct {
	Domains []string `json:"domains,omitempty"`
	IPs     []string `json:"ips,omitempty"`
	Strings []string `json:"strings,omitempty"`
	URLs    []string `json:"urls,omitempty"`
}

// PyPIMalPackagesOrigin is one origin record from the OSSF malicious
// packages feed (one upstream advisory may carry several when multiple
// detectors flagged the same release).
type PyPIMalPackagesOrigin struct {
	ID           string                 `json:"id,omitempty"`
	ImportTime   time.Time              `json:"import_time,omitzero"`
	ModifiedTime time.Time              `json:"modified_time,omitzero"`
	Ranges       []PyPIMalPackagesRange `json:"ranges,omitempty"`
	SHA256       string                 `json:"sha256,omitempty"`
	Source       string                 `json:"source,omitempty"`
	Versions     []string               `json:"versions,omitempty"`
}

// PyPIMalPackagesRange mirrors the `ranges[]` element on a malicious
// origin record — same shape as the OSV core Range but lives on a
// different parent so we keep it local to the ecosystem.
type PyPIMalPackagesRange struct {
	Events []Event `json:"events,omitempty"`
	Repo   string  `json:"repo,omitempty"`
	Type   string  `json:"type,omitempty"`
}

// AffectedEcoPyPI is `affected[].ecosystem_specific` for PyPI. PyPI
// advisories carry per-affected severity (sometimes a CVSS array,
// sometimes a single string label like "HIGH" produced by OSS-Fuzz
// importers) plus a fixed_range string used by malicious-packages
// tooling.
type AffectedEcoPyPI struct {
	FixedRange string          `json:"fixed_range,omitempty"`
	Severity   PyPIEcoSeverity `json:"severity,omitempty"`
}

func (*AffectedEcoPyPI) isAffectedEcoSpec() {}

// PyPIEcoSeverity captures both shapes upstream uses for
// `affected[].ecosystem_specific.severity`: a CVSS array (the OSV
// schema's []Severity) or a bare label string (e.g. "HIGH"). The
// custom Unmarshal/Marshal pair preserves whichever form upstream
// emitted so a round-trip never silently rewrites the document.
type PyPIEcoSeverity struct {
	Items []Severity
	Label string
}

func (s PyPIEcoSeverity) MarshalJSON() ([]byte, error) {
	if s.Label != "" {
		return json.Marshal(s.Label)
	}
	if len(s.Items) > 0 {
		return json.Marshal(s.Items)
	}
	return []byte("null"), nil
}

func (s *PyPIEcoSeverity) UnmarshalJSON(b []byte) error {
	if len(b) == 0 || string(b) == "null" {
		*s = PyPIEcoSeverity{}
		return nil
	}
	switch b[0] {
	case '"':
		var v string
		if err := json.Unmarshal(b, &v); err != nil {
			return err
		}
		*s = PyPIEcoSeverity{Label: v}
		return nil
	case '[':
		var v []Severity
		if err := json.Unmarshal(b, &v); err != nil {
			return err
		}
		*s = PyPIEcoSeverity{Items: v}
		return nil
	default:
		return fmt.Errorf("PyPIEcoSeverity: unexpected JSON %q", b)
	}
}

// AffectedDBPyPI is `affected[].database_specific` for PyPI. CWES is
// populated for malicious packages converted from the OSSF feed; the
// rest is GHSA / source provenance.
type AffectedDBPyPI struct {
	CWEs                          []PyPICWE `json:"cwes,omitempty"`
	FixedRange                    string    `json:"fixed_range,omitempty"`
	LastKnownAffectedVersionRange string    `json:"last_known_affected_version_range,omitempty"`
	Source                        string    `json:"source,omitempty"`
}

func (*AffectedDBPyPI) isAffectedDBSpec() {}

// PyPICWE is the malicious-packages CWE detail.
type PyPICWE struct {
	CWEID       string `json:"cweId,omitempty"`
	Description string `json:"description,omitempty"`
	Name        string `json:"name,omitempty"`
}

// RangeDBPyPI is `affected[].ranges[].database_specific` for PyPI.
// PyPI does not currently use range-level database_specific, but the
// dispatch table requires a concrete type. Empty struct round-trips as
// `{}` only if upstream actually emits it; otherwise it is never
// instantiated (Parse skips zero/null blobs).
type RangeDBPyPI struct{}

func (*RangeDBPyPI) isRangeDBSpec() {}

func init() {
	register("PyPI", ecosystemDispatch{
		top:    func() TopSpecific { return &TopPyPI{} },
		affEco: func() AffectedEcoSpec { return &AffectedEcoPyPI{} },
		affDB:  func() AffectedDBSpec { return &AffectedDBPyPI{} },
		rngDB:  func() RangeDBSpec { return &RangeDBPyPI{} },
	})
}
