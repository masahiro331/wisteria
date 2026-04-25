// Package osv defines parser types for OSV.dev advisory JSON.
//
// All upstream fields are declared as typed Go fields so a parse + re-marshal
// round-trip preserves every key the upstream catalog emits. Free-form
// per-source blobs (`database_specific`, `ecosystem_specific`,
// `credits[].contact[]` element shapes that vary across ecosystems) are
// kept as `json.RawMessage` rather than dropped.
package osv

import (
	"encoding/json"
	"time"
)

// Record is one OSV advisory file (OSV schema 1.x).
type Record struct {
	SchemaVersion    string          `json:"schema_version,omitempty"`
	ID               string          `json:"id"`
	Modified         time.Time       `json:"modified,omitzero"`
	Published        time.Time       `json:"published,omitzero"`
	Withdrawn        time.Time       `json:"withdrawn,omitzero"`
	Aliases          []string        `json:"aliases,omitempty"`
	Related          []string        `json:"related,omitempty"`
	Upstream         []string        `json:"upstream,omitempty"`
	Summary          string          `json:"summary,omitempty"`
	Details          string          `json:"details,omitempty"`
	Severity         []Severity      `json:"severity,omitempty"`
	Affected         []Affected      `json:"affected,omitempty"`
	References       []Reference     `json:"references,omitempty"`
	Credits          []Credit        `json:"credits,omitempty"`
	DatabaseSpecific json.RawMessage `json:"database_specific,omitempty"`
}

// Severity is one severity assessment, typically a CVSS string.
type Severity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// Reference is one external link attached to an advisory.
type Reference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// Credit is one entity credited with discovering or reporting the issue.
type Credit struct {
	Name    string   `json:"name"`
	Contact []string `json:"contact,omitempty"`
	Type    string   `json:"type,omitempty"`
}

// Affected is one affected package + version range entry.
type Affected struct {
	Package           Package         `json:"package"`
	Severity          []Severity      `json:"severity,omitempty"`
	Ranges            []Range         `json:"ranges,omitempty"`
	Versions          []string        `json:"versions,omitempty"`
	EcosystemSpecific json.RawMessage `json:"ecosystem_specific,omitempty"`
	DatabaseSpecific  json.RawMessage `json:"database_specific,omitempty"`
}

// Package identifies a software unit affected by the advisory.
type Package struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	PURL      string `json:"purl,omitempty"`
}

// Range is one version range with a series of introduced/fixed/limit events.
type Range struct {
	Type             string          `json:"type"`
	Repo             string          `json:"repo,omitempty"`
	Events           []Event         `json:"events"`
	DatabaseSpecific json.RawMessage `json:"database_specific,omitempty"`
}

// Event marks a transition (introduced / fixed / last_affected / limit) in
// a Range. Exactly one field is non-empty per OSV spec; we keep them all so
// callers can dispatch on which field is set.
type Event struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}
