// Package osv defines parser types for OSV.dev advisory JSON.
// Field names follow the OSV schema; only the fields wisteria's pipeline
// reads are declared.
package osv

import "encoding/json"

// Record is one OSV advisory file.
type Record struct {
	ID         string      `json:"id"`
	Aliases    []string    `json:"aliases,omitempty"`
	Summary    string      `json:"summary,omitempty"`
	Details    string      `json:"details,omitempty"`
	References []Reference `json:"references,omitempty"`
	Severity   []Severity  `json:"severity,omitempty"`
	Affected   []Affected  `json:"affected,omitempty"`
}

// Reference is one external link attached to an advisory.
type Reference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// Severity is one severity assessment, typically a CVSS string.
type Severity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// Affected is one affected package + version range entry.
type Affected struct {
	Package           Package         `json:"package"`
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
	Type   string  `json:"type"`
	Repo   string  `json:"repo,omitempty"`
	Events []Event `json:"events"`
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
