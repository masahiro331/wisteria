package osv

import (
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// RecordPyPI is one OSV advisory from the PyPI ecosystem.
//
// The shape lives entirely in this file: the embedded `Record`
// supplies the schema-common fields, `Affected []AffectedPyPI`
// carries the per-package metadata typed for PyPI, and
// `DatabaseSpecific TopPyPI` types the record-level GHSA / malicious-
// packages payload that osv.dev attaches under `database_specific`.
type RecordPyPI struct {
	Record
	Affected         []AffectedPyPI `json:"affected,omitempty"`
	DatabaseSpecific TopPyPI        `json:"database_specific,omitzero"`
}

// Base satisfies OSVRecord by exposing the embedded common fields.
func (r *RecordPyPI) Base() *Record { return &r.Record }

// AffectedPyPI is the PyPI shape of `affected[]`. EcosystemSpecific is
// the per-affected `ecosystem_specific` block (CVSS array or label
// string under `severity`, plus `fixed_range` for malicious-packages
// imports), DatabaseSpecific is `affected[].database_specific` and
// Ranges carries PyPI ranges (database_specific is empty for PyPI).
type AffectedPyPI struct {
	AffectedBase
	Ranges            []RangePyPI     `json:"ranges,omitempty"`
	EcosystemSpecific AffectedEcoPyPI `json:"ecosystem_specific,omitzero"`
	DatabaseSpecific  AffectedDBPyPI  `json:"database_specific,omitzero"`
}

// RangePyPI is the PyPI shape of `affected[].ranges[]`. PyPI does not
// emit range-level `database_specific` today, so the type adds
// nothing beyond the base — but we still declare it so the wrapper
// type can grow without touching every affected user later.
type RangePyPI struct {
	RangeBase
}

// TopPyPI is `database_specific` at the record root for PyPI
// advisories. The malicious-packages-origins / iocs blobs only appear
// on entries converted from the OSSF malicious-packages feed; for
// normal GHSA imports those fields are absent and the GHSA review
// metadata (cwe_ids, github_reviewed, ...) is what's populated.
type TopPyPI struct {
	CWEIDs                   []string                `json:"cwe_ids,omitempty"`
	GitHubReviewed           bool                    `json:"github_reviewed,omitempty"`
	GitHubReviewedAt         time.Time               `json:"github_reviewed_at,omitzero"`
	IOCs                     *PyPIIOCs               `json:"iocs,omitempty"`
	MaliciousPackagesOrigins []PyPIMalPackagesOrigin `json:"malicious-packages-origins,omitempty"`
	NVDPublishedAt           time.Time               `json:"nvd_published_at,omitzero"`
	Severity                 string                  `json:"severity,omitempty"`
}

// PyPIIOCs holds indicator-of-compromise data for malicious-package
// reports in the PyPI feed.
type PyPIIOCs struct {
	Domains []string `json:"domains,omitempty"`
	IPs     []string `json:"ips,omitempty"`
	Strings []string `json:"strings,omitempty"`
	URLs    []string `json:"urls,omitempty"`
}

// PyPIMalPackagesOrigin is one origin record from the OSSF malicious
// packages feed (one upstream advisory may carry several when
// multiple detectors flagged the same release).
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

// AffectedEcoPyPI is `affected[].ecosystem_specific` for PyPI.
type AffectedEcoPyPI struct {
	FixedRange string          `json:"fixed_range,omitempty"`
	Severity   PyPIEcoSeverity `json:"severity,omitzero"`
}

// PyPIEcoSeverity captures both shapes upstream uses for
// `affected[].ecosystem_specific.severity`: a CVSS array (the OSV
// schema's []Severity) or a bare label string (e.g. "HIGH"). The
// custom Unmarshal/Marshal pair preserves whichever form upstream
// emitted so a round-trip never silently rewrites the document.
type PyPIEcoSeverity struct {
	Items []Severity
	Label string
}

// IsZero is consulted by Go 1.24's `omitzero` so a fully-empty
// PyPIEcoSeverity is omitted from JSON output rather than emitted as
// `null`.
func (s PyPIEcoSeverity) IsZero() bool { return len(s.Items) == 0 && s.Label == "" }

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

// AffectedDBPyPI is `affected[].database_specific` for PyPI.
type AffectedDBPyPI struct {
	CWEs                          []PyPICWE `json:"cwes,omitempty"`
	FixedRange                    string    `json:"fixed_range,omitempty"`
	LastKnownAffectedVersionRange string    `json:"last_known_affected_version_range,omitempty"`
	Source                        string    `json:"source,omitempty"`
}

// PyPICWE is the malicious-packages CWE detail.
type PyPICWE struct {
	CWEID       string `json:"cweId,omitempty"`
	Description string `json:"description,omitempty"`
	Name        string `json:"name,omitempty"`
}

// NewRecordPyPI parses one PyPI OSV record from r. The Ecosystem
// field on the embedded `Record` is set so downstream code can
// dispatch on it without a type switch.
func NewRecordPyPI(r io.Reader) (*RecordPyPI, error) {
	var rec RecordPyPI
	if err := json.NewDecoder(r).Decode(&rec); err != nil {
		return nil, fmt.Errorf("osv: parse PyPI: %w", err)
	}
	rec.Ecosystem = EcosystemPyPI
	return &rec, nil
}
