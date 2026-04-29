// Package osv defines parser types for OSV.dev advisory JSON.
//
// Each upstream ecosystem (PyPI, Ubuntu, Debian, ...) ships its own
// `database_specific` and `ecosystem_specific` payloads, so the
// package gives every ecosystem its own concrete `RecordX` struct
// that embeds the shared `Record` base. The base carries the schema
// fields that every OSV record has in common (id, aliases, summary,
// references, ...); the ecosystem-specific bits live as plain Go
// fields on the wrapping struct so callers see a fully typed shape.
//
// To decode a record, callers either:
//
//   - use the matching `NewRecord<Eco>(reader)` constructor (returns
//     the concrete `*RecordPyPI` etc., type-safe at the call site), or
//   - go through `Parse(eco, reader)` when the ecosystem is only known
//     dynamically (walker / pipeline path); the result satisfies the
//     `OSVRecord` interface and a type assertion recovers the concrete
//     value.
//
// Round-trip preservation is the load-bearing invariant: the typed
// schema must marshal back to JSON semantically equal to the input.
// `tools/schema-coverage` enforces this across the full corpus.
package osv

import (
	"fmt"
	"io"
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
type OSVRecord interface {
	Base() *Record
}

// Parse reads one OSV record from r and returns it as an OSVRecord
// chosen by eco. The function exists for callers that learn the
// ecosystem dynamically (walker / pipeline). When the ecosystem is
// fixed at the call site, prefer the matching `NewRecord<Eco>` —
// it is type-safe and avoids the assertion on the caller side.
//
// Each entry in the dispatch table delegates to the concrete
// `NewRecord<Eco>` so the parsing logic always lives next to the
// ecosystem's typed shape, never here.
func Parse(eco Ecosystem, r io.Reader) (OSVRecord, error) {
	idx := int(eco)
	if idx < 0 || idx >= len(parseDispatch) || parseDispatch[idx] == nil {
		return nil, fmt.Errorf("osv: unknown ecosystem %d", idx)
	}
	return parseDispatch[idx](r)
}

// parseDispatch maps each Ecosystem constant to its concrete
// `NewRecord*` factory. Indices match the constant block in this file
// so a missed registration shows up as a nil entry at parse time
// (Parse hard-errors). New ecosystems must extend both the constant
// block and this table.
var parseDispatch = [...]func(io.Reader) (OSVRecord, error){
	EcosystemAlmaLinux:                  func(r io.Reader) (OSVRecord, error) { return NewRecordAlmaLinux(r) },
	EcosystemAlpaquita:                  func(r io.Reader) (OSVRecord, error) { return NewRecordAlpaquita(r) },
	EcosystemAlpine:                     func(r io.Reader) (OSVRecord, error) { return NewRecordAlpine(r) },
	EcosystemAndroid:                    func(r io.Reader) (OSVRecord, error) { return NewRecordAndroid(r) },
	EcosystemAzureLinux:                 func(r io.Reader) (OSVRecord, error) { return NewRecordAzureLinux(r) },
	EcosystemBellSoftHardenedContainers: func(r io.Reader) (OSVRecord, error) { return NewRecordBellSoftHardenedContainers(r) },
	EcosystemBitnami:                    func(r io.Reader) (OSVRecord, error) { return NewRecordBitnami(r) },
	EcosystemCRAN:                       func(r io.Reader) (OSVRecord, error) { return NewRecordCRAN(r) },
	EcosystemChainguard:                 func(r io.Reader) (OSVRecord, error) { return NewRecordChainguard(r) },
	EcosystemCleanStart:                 func(r io.Reader) (OSVRecord, error) { return NewRecordCleanStart(r) },
	EcosystemCratesIO:                   func(r io.Reader) (OSVRecord, error) { return NewRecordCratesIO(r) },
	EcosystemDebian:                     func(r io.Reader) (OSVRecord, error) { return NewRecordDebian(r) },
	EcosystemEcho:                       func(r io.Reader) (OSVRecord, error) { return NewRecordEcho(r) },
	EcosystemGHC:                        func(r io.Reader) (OSVRecord, error) { return NewRecordGHC(r) },
	EcosystemGIT:                        func(r io.Reader) (OSVRecord, error) { return NewRecordGIT(r) },
	EcosystemGSD:                        func(r io.Reader) (OSVRecord, error) { return NewRecordGSD(r) },
	EcosystemGeneric:                    func(r io.Reader) (OSVRecord, error) { return NewRecordGeneric(r) },
	EcosystemGitHubActions:              func(r io.Reader) (OSVRecord, error) { return NewRecordGitHubActions(r) },
	EcosystemGo:                         func(r io.Reader) (OSVRecord, error) { return NewRecordGo(r) },
	EcosystemHackage:                    func(r io.Reader) (OSVRecord, error) { return NewRecordHackage(r) },
	EcosystemHex:                        func(r io.Reader) (OSVRecord, error) { return NewRecordHex(r) },
	EcosystemJulia:                      func(r io.Reader) (OSVRecord, error) { return NewRecordJulia(r) },
	EcosystemLinux:                      func(r io.Reader) (OSVRecord, error) { return NewRecordLinux(r) },
	EcosystemMageia:                     func(r io.Reader) (OSVRecord, error) { return NewRecordMageia(r) },
	EcosystemMaven:                      func(r io.Reader) (OSVRecord, error) { return NewRecordMaven(r) },
	EcosystemMinimOS:                    func(r io.Reader) (OSVRecord, error) { return NewRecordMinimOS(r) },
	EcosystemNuGet:                      func(r io.Reader) (OSVRecord, error) { return NewRecordNuGet(r) },
	EcosystemOSSFuzz:                    func(r io.Reader) (OSVRecord, error) { return NewRecordOSSFuzz(r) },
	EcosystemPackagist:                  func(r io.Reader) (OSVRecord, error) { return NewRecordPackagist(r) },
	EcosystemPub:                        func(r io.Reader) (OSVRecord, error) { return NewRecordPub(r) },
	EcosystemPyPI:                       func(r io.Reader) (OSVRecord, error) { return NewRecordPyPI(r) },
	EcosystemRedHat:                     func(r io.Reader) (OSVRecord, error) { return NewRecordRedHat(r) },
	EcosystemRockyLinux:                 func(r io.Reader) (OSVRecord, error) { return NewRecordRockyLinux(r) },
	EcosystemRoot:                       func(r io.Reader) (OSVRecord, error) { return NewRecordRoot(r) },
	EcosystemRubyGems:                   func(r io.Reader) (OSVRecord, error) { return NewRecordRubyGems(r) },
	EcosystemSUSE:                       func(r io.Reader) (OSVRecord, error) { return NewRecordSUSE(r) },
	EcosystemSwiftURL:                   func(r io.Reader) (OSVRecord, error) { return NewRecordSwiftURL(r) },
	EcosystemUVI:                        func(r io.Reader) (OSVRecord, error) { return NewRecordUVI(r) },
	EcosystemUbuntu:                     func(r io.Reader) (OSVRecord, error) { return NewRecordUbuntu(r) },
	EcosystemVSCode:                     func(r io.Reader) (OSVRecord, error) { return NewRecordVSCode(r) },
	EcosystemWolfi:                      func(r io.Reader) (OSVRecord, error) { return NewRecordWolfi(r) },
	EcosystemNpm:                        func(r io.Reader) (OSVRecord, error) { return NewRecordNpm(r) },
	EcosystemOpam:                       func(r io.Reader) (OSVRecord, error) { return NewRecordOpam(r) },
	EcosystemOpenEuler:                  func(r io.Reader) (OSVRecord, error) { return NewRecordOpenEuler(r) },
	EcosystemOpenSUSE:                   func(r io.Reader) (OSVRecord, error) { return NewRecordOpenSUSE(r) },
}
