// Package osv defines parser types for OSV.dev advisory JSON.
//
// All upstream fields are declared as typed Go fields so a parse +
// re-marshal round-trip preserves every key the upstream catalog emits
// (the design's "1 byte not lost" rule, §7).
//
// The free-form `database_specific` and `ecosystem_specific` blobs vary
// by upstream ecosystem (PyPI, npm, Debian, Ubuntu, ...), so each
// ecosystem owns its own typed structs and the package dispatches by
// the ecosystem directory name carved out of the file path. Use Parse
// to decode an OSV record; raw `json.Unmarshal` into Record is no
// longer supported because the discriminated-union fields would not
// know which concrete type to instantiate.
package osv

import "time"

// Record is one OSV advisory file (OSV schema 1.x).
//
// DatabaseSpecific is a discriminated-union value whose concrete type
// is chosen by Parse based on the ecosystem extracted from the file
// path. Marshaling a Record always emits the same JSON shape upstream
// produced because each ecosystem-specific struct mirrors the upstream
// keys verbatim.
type Record struct {
	SchemaVersion    string      `json:"schema_version,omitempty"`
	ID               string      `json:"id"`
	Modified         time.Time   `json:"modified,omitzero"`
	Published        time.Time   `json:"published,omitzero"`
	Withdrawn        time.Time   `json:"withdrawn,omitzero"`
	Aliases          []string    `json:"aliases,omitempty"`
	Related          []string    `json:"related,omitempty"`
	Upstream         []string    `json:"upstream,omitempty"`
	Summary          string      `json:"summary,omitempty"`
	Details          string      `json:"details,omitempty"`
	Severity         []Severity  `json:"severity,omitempty"`
	Affected         []Affected  `json:"affected,omitempty"`
	References       []Reference `json:"references,omitempty"`
	Credits          []Credit    `json:"credits,omitempty"`
	DatabaseSpecific TopSpecific `json:"database_specific,omitempty"`
}

// Severity is one severity assessment, typically a CVSS string.
//
// Both fields are `omitempty` because the upstream corpus contains
// records that emit only one of (type, score) — e.g. Ubuntu publishes
// `{"score": "medium"}` with no type tag.
type Severity struct {
	Type  string `json:"type,omitempty"`
	Score string `json:"score,omitempty"`
}

// Reference is one external link attached to an advisory.
//
// Both fields are `omitempty` because the upstream corpus contains
// references with only `type` set (no URL) — observed in GSD entries.
type Reference struct {
	Type string `json:"type,omitempty"`
	URL  string `json:"url,omitempty"`
}

// Credit is one entity credited with discovering or reporting the issue.
type Credit struct {
	Name    string   `json:"name"`
	Contact []string `json:"contact,omitempty"`
	Type    string   `json:"type,omitempty"`
}

// Affected is one affected package + version range entry.
//
// Package is a pointer because the upstream corpus contains affected
// entries with no package metadata at all — e.g. Debian / GIT records
// whose only identity is a repo URL on the Range. A value-typed field
// would silently round-trip as `"package": {}`.
//
// EcosystemSpecific and DatabaseSpecific are discriminated-union fields
// chosen by Parse on the same ecosystem-from-path basis as Record.
type Affected struct {
	Package           *Package        `json:"package,omitempty"`
	Severity          []Severity      `json:"severity,omitempty"`
	Ranges            []Range         `json:"ranges,omitempty"`
	Versions          []string        `json:"versions,omitempty"`
	EcosystemSpecific AffectedEcoSpec `json:"ecosystem_specific,omitempty"`
	DatabaseSpecific  AffectedDBSpec  `json:"database_specific,omitempty"`
}

// Package identifies a software unit affected by the advisory.
type Package struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	PURL      string `json:"purl,omitempty"`
}

// Range is one version range with a series of introduced/fixed/limit events.
type Range struct {
	Type             string      `json:"type"`
	Repo             string      `json:"repo,omitempty"`
	Events           []Event     `json:"events"`
	DatabaseSpecific RangeDBSpec `json:"database_specific,omitempty"`
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

// TopSpecific is the discriminated-union for `Record.database_specific`.
// Each ecosystem implements its own concrete struct (TopPyPI,
// TopMaven, ...). The marker method is deliberately named so a stray
// json.Unmarshal target cannot accidentally satisfy it.
type TopSpecific interface {
	isTopSpecific()
}

// AffectedEcoSpec is the discriminated-union for
// `Affected.ecosystem_specific`.
type AffectedEcoSpec interface {
	isAffectedEcoSpec()
}

// AffectedDBSpec is the discriminated-union for
// `Affected.database_specific`.
type AffectedDBSpec interface {
	isAffectedDBSpec()
}

// RangeDBSpec is the discriminated-union for
// `Affected.ranges[].database_specific`.
type RangeDBSpec interface {
	isRangeDBSpec()
}
