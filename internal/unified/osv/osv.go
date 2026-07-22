// Package osv defines the shared foundation for OSV.dev advisory JSON:
// the schema fields every record has in common plus the ecosystem
// registry.
//
// Each upstream ecosystem (PyPI, Ubuntu, Debian, ...) ships its own
// `database_specific` and `ecosystem_specific` payloads. This package
// carries only the parts common to all of them — the `Record` base
// (id, aliases, summary, references, ...), the shared `AffectedBase` /
// `RangeBase`, the `Ecosystem` enum + name table, and the `OSVRecord`
// interface that every concrete record satisfies.
//
// The per-ecosystem `RecordX` structs (which embed `Record` and add
// their typed `database_specific` / `ecosystem_specific`), their
// `NewRecord<Eco>` constructors, and the dynamic `Parse(eco, reader)`
// dispatch all live in the sibling `ecosystem` subpackage. That
// package imports this one; the dependency is one-way (ecosystem →
// osv) so the base types stay free of the 44-ecosystem tail.
//
// Round-trip preservation is the load-bearing invariant: the typed
// schema must marshal back to JSON semantically equal to the input.
// `tools/schema-coverage` enforces this across the full corpus.
package osv

import (
	"fmt"
	"strings"
	"time"
)

// Ecosystem identifies one upstream OSV bucket. Values match the
// directory names that osv.dev ships under `<root>/osv/<dir>/...`,
// with whitespace replaced by `_` so the on-disk dir `Red Hat` maps
// to `EcosystemRedHat` (string form `Red Hat`, normalized form
// `Red_Hat` mirrors the walker / writer routing).
type Ecosystem int

// The constant order is sorted by upstream directory name. New
// ecosystems should be appended at the end so existing downstream
// switch statements stay compile-error-driven for additions.
const (
	EcosystemAlmaLinux Ecosystem = iota
	EcosystemAlpaquita
	EcosystemAlpine
	EcosystemAndroid
	EcosystemAzureLinux
	EcosystemBellSoftHardenedContainers
	EcosystemBitnami
	EcosystemCRAN
	EcosystemChainguard
	EcosystemCleanStart
	EcosystemCratesIO
	EcosystemDebian
	EcosystemEcho
	EcosystemGHC
	EcosystemGIT
	EcosystemGSD
	EcosystemGeneric
	EcosystemGitHubActions
	EcosystemGo
	EcosystemHackage
	EcosystemHex
	EcosystemJulia
	EcosystemLinux
	EcosystemMageia
	EcosystemMaven
	EcosystemMinimOS
	EcosystemNuGet
	EcosystemOSSFuzz
	EcosystemPackagist
	EcosystemPub
	EcosystemPyPI
	EcosystemRedHat
	EcosystemRockyLinux
	EcosystemRoot
	EcosystemRubyGems
	EcosystemSUSE
	EcosystemSwiftURL
	EcosystemUVI
	EcosystemUbuntu
	EcosystemVSCode
	EcosystemWolfi
	EcosystemNpm
	EcosystemOpam
	EcosystemOpenEuler
	EcosystemOpenSUSE
	EcosystemTuxCare
)

// ecosystemName maps each Ecosystem value to its on-disk directory
// name (verbatim, including spaces and dots). Order mirrors the
// constant block above so sentinel `len(ecosystemName)` doubles as
// the count of registered ecosystems.
var ecosystemName = [...]string{
	EcosystemAlmaLinux:                  "AlmaLinux",
	EcosystemAlpaquita:                  "Alpaquita",
	EcosystemAlpine:                     "Alpine",
	EcosystemAndroid:                    "Android",
	EcosystemAzureLinux:                 "Azure Linux",
	EcosystemBellSoftHardenedContainers: "BellSoft Hardened Containers",
	EcosystemBitnami:                    "Bitnami",
	EcosystemCRAN:                       "CRAN",
	EcosystemChainguard:                 "Chainguard",
	EcosystemCleanStart:                 "CleanStart",
	EcosystemCratesIO:                   "crates.io",
	EcosystemDebian:                     "Debian",
	EcosystemEcho:                       "Echo",
	EcosystemGHC:                        "GHC",
	EcosystemGIT:                        "GIT",
	EcosystemGSD:                        "GSD",
	EcosystemGeneric:                    "Generic",
	EcosystemGitHubActions:              "GitHub Actions",
	EcosystemGo:                         "Go",
	EcosystemHackage:                    "Hackage",
	EcosystemHex:                        "Hex",
	EcosystemJulia:                      "Julia",
	EcosystemLinux:                      "Linux",
	EcosystemMageia:                     "Mageia",
	EcosystemMaven:                      "Maven",
	EcosystemMinimOS:                    "MinimOS",
	EcosystemNuGet:                      "NuGet",
	EcosystemOSSFuzz:                    "OSS-Fuzz",
	EcosystemPackagist:                  "Packagist",
	EcosystemPub:                        "Pub",
	EcosystemPyPI:                       "PyPI",
	EcosystemRedHat:                     "Red Hat",
	EcosystemRockyLinux:                 "Rocky Linux",
	EcosystemRoot:                       "Root",
	EcosystemRubyGems:                   "RubyGems",
	EcosystemSUSE:                       "SUSE",
	EcosystemSwiftURL:                   "SwiftURL",
	EcosystemUVI:                        "UVI",
	EcosystemUbuntu:                     "Ubuntu",
	EcosystemVSCode:                     "VSCode",
	EcosystemWolfi:                      "Wolfi",
	EcosystemNpm:                        "npm",
	EcosystemOpam:                       "opam",
	EcosystemOpenEuler:                  "openEuler",
	EcosystemOpenSUSE:                   "openSUSE",
	EcosystemTuxCare:                    "TuxCare",
}

// String returns the on-disk directory name for this ecosystem
// (verbatim, including spaces). Use `Normalized()` to get the
// space-normalized form used for source-tag and routing.
func (e Ecosystem) String() string {
	if int(e) < 0 || int(e) >= len(ecosystemName) {
		return fmt.Sprintf("Ecosystem(%d)", int(e))
	}
	return ecosystemName[e]
}

// Normalized returns the ecosystem name with whitespace replaced by
// `_`, matching how walker / writer / source-tag tables index the
// ecosystem.
func (e Ecosystem) Normalized() string {
	return strings.ReplaceAll(e.String(), " ", "_")
}

// EcosystemFromString resolves a directory name (verbatim or
// space-normalized) back to the Ecosystem constant. Unknown names
// hard-error so a fresh upstream bucket cannot silently land in the
// pipeline.
func EcosystemFromString(name string) (Ecosystem, error) {
	for i, n := range &ecosystemName {
		if n == name {
			return Ecosystem(i), nil
		}
	}
	// Try space-normalized form (Red_Hat → Red Hat).
	denormalized := strings.ReplaceAll(name, "_", " ")
	for i, n := range &ecosystemName {
		if n == denormalized {
			return Ecosystem(i), nil
		}
	}
	return 0, fmt.Errorf("osv: unknown ecosystem %q", name)
}

// Record carries the OSV schema fields shared by every ecosystem.
// Concrete `RecordX` types embed it and add their own
// `Affected []AffectedX` plus `DatabaseSpecific TopX`.
type Record struct {
	Ecosystem     Ecosystem   `json:"-"`
	SchemaVersion string      `json:"schema_version,omitempty"`
	ID            string      `json:"id"`
	Modified      time.Time   `json:"modified,omitzero"`
	Published     time.Time   `json:"published,omitzero"`
	Withdrawn     time.Time   `json:"withdrawn,omitzero"`
	Aliases       []string    `json:"aliases,omitempty"`
	Related       []string    `json:"related,omitempty"`
	Upstream      []string    `json:"upstream,omitempty"`
	Summary       string      `json:"summary,omitempty"`
	Details       string      `json:"details,omitempty"`
	Severity      []Severity  `json:"severity,omitempty"`
	References    []Reference `json:"references,omitempty"`
	Credits       []Credit    `json:"credits,omitempty"`
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

// Package identifies a software unit affected by the advisory.
type Package struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	PURL      string `json:"purl,omitempty"`
}

// Event marks a transition (introduced / fixed / last_affected /
// limit) in a Range. Exactly one field is non-empty per OSV spec; we
// keep them all so callers can dispatch on which field is set.
type Event struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}

// AffectedBase carries the OSV `affected[]` fields shared across every
// ecosystem. Per-ecosystem `AffectedX` types embed it and add their
// own typed `EcosystemSpecific` / `DatabaseSpecific` (plus a
// `RangeX []RangeX` if range-level metadata is involved).
//
// Package is a pointer because the upstream corpus contains affected
// entries with no package metadata at all — e.g. Debian / GIT records
// whose only identity is a repo URL on the Range. A value-typed field
// would silently round-trip as `"package": {}`.
type AffectedBase struct {
	Package  *Package   `json:"package,omitempty"`
	Severity []Severity `json:"severity,omitempty"`
	Versions []string   `json:"versions,omitempty"`
}

// Base returns the embedded AffectedBase. It is promoted into every
// per-ecosystem `*AffectedX`, so callers holding an affected entry as
// `any` (advisory.AffectedRecord.OSV) can reach the shared fields via a
// single interface assertion instead of a 45-type switch — the same
// role OSVRecord.Base plays for records.
func (a *AffectedBase) Base() *AffectedBase { return a }

// RangeBase carries the OSV `affected[].ranges[]` fields shared across
// every ecosystem. Per-ecosystem `RangeX` types embed it and add the
// ecosystem-specific `database_specific`.
type RangeBase struct {
	Type   string  `json:"type"`
	Repo   string  `json:"repo,omitempty"`
	Events []Event `json:"events"`
}

// OSVRecord is satisfied by every concrete `RecordX`. It exists so
// callers that have a record but do not yet need to look at the
// ecosystem-specific tail (e.g. walker indexers, downstream
// serializers) can hold it in one variable without a giant union
// type. `Base()` returns the embedded `Record` so the common fields
// are reachable without a type switch.
//
// `AffectedAny` returns the record's per-ecosystem `Affected` slice
// with each element boxed as `any` (the concrete `*AffectedX`
// pointer is preserved). It lets callers that merge across
// ecosystems pull the affected entries without a per-type switch or
// reflection — every `RecordX` implements it, so the compiler
// guarantees full coverage as new ecosystems are added.
//
// `CWEIDs` returns the record's CWE identifiers when its typed
// `database_specific` carries them (GHSA-family `cwe_ids`, opam
// `cwe`), nil otherwise. Mandatory for the same reason as
// AffectedAny: a new ecosystem cannot silently drop its CWE data.
type OSVRecord interface {
	Base() *Record
	AffectedAny() []any
	CWEIDs() []string
}
