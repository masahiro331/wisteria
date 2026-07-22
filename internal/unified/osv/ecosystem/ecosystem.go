// Package ecosystem holds the per-ecosystem OSV record schemas.
//
// Every upstream OSV bucket (PyPI, Ubuntu, Debian, Maven, ...) gets
// its own concrete `RecordX` struct that embeds the shared `osv.Record`
// base and adds its typed `database_specific` / `ecosystem_specific`
// payloads, plus a `NewRecord<Eco>` constructor. `Parse(eco, reader)`
// dispatches to the right constructor when the ecosystem is only known
// dynamically (walker / pipeline path) and returns an `osv.OSVRecord`.
//
// This package imports osv for the base types and the `Ecosystem`
// enum; the dependency is one-way (ecosystem → osv). Keeping the
// 44-ecosystem tail here keeps the osv package itself small.
package ecosystem

import (
	"fmt"
	"io"

	"github.com/masahiro331/wisteria/internal/unified/osv"
)

// affectedAny boxes each element of a per-ecosystem `[]AffectedX`
// slice as `any`, returning a slice of pointers to independent
// copies. Concrete `RecordX.AffectedAny` methods delegate here so the
// boxing logic lives in one place.
func affectedAny[T any](in []T) []any {
	out := make([]any, len(in))
	for i := range in {
		v := in[i]
		out[i] = &v
	}
	return out
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
func Parse(eco osv.Ecosystem, r io.Reader) (osv.OSVRecord, error) {
	idx := int(eco)
	if idx < 0 || idx >= len(parseDispatch) || parseDispatch[idx] == nil {
		return nil, fmt.Errorf("ecosystem: unknown ecosystem %d", idx)
	}
	return parseDispatch[idx](r)
}

// parseDispatch maps each Ecosystem constant to its concrete
// `NewRecord*` factory. Indices match the `osv.Ecosystem` constant
// block (in the osv package) so a missed registration shows up as a
// nil entry at parse time (Parse hard-errors). New ecosystems must
// extend both that constant block and this table.
var parseDispatch = [...]func(io.Reader) (osv.OSVRecord, error){
	osv.EcosystemAlmaLinux:                  func(r io.Reader) (osv.OSVRecord, error) { return NewRecordAlmaLinux(r) },
	osv.EcosystemAlpaquita:                  func(r io.Reader) (osv.OSVRecord, error) { return NewRecordAlpaquita(r) },
	osv.EcosystemAlpine:                     func(r io.Reader) (osv.OSVRecord, error) { return NewRecordAlpine(r) },
	osv.EcosystemAndroid:                    func(r io.Reader) (osv.OSVRecord, error) { return NewRecordAndroid(r) },
	osv.EcosystemAzureLinux:                 func(r io.Reader) (osv.OSVRecord, error) { return NewRecordAzureLinux(r) },
	osv.EcosystemBellSoftHardenedContainers: func(r io.Reader) (osv.OSVRecord, error) { return NewRecordBellSoftHardenedContainers(r) },
	osv.EcosystemBitnami:                    func(r io.Reader) (osv.OSVRecord, error) { return NewRecordBitnami(r) },
	osv.EcosystemCRAN:                       func(r io.Reader) (osv.OSVRecord, error) { return NewRecordCRAN(r) },
	osv.EcosystemChainguard:                 func(r io.Reader) (osv.OSVRecord, error) { return NewRecordChainguard(r) },
	osv.EcosystemCleanStart:                 func(r io.Reader) (osv.OSVRecord, error) { return NewRecordCleanStart(r) },
	osv.EcosystemCratesIO:                   func(r io.Reader) (osv.OSVRecord, error) { return NewRecordCratesIO(r) },
	osv.EcosystemDebian:                     func(r io.Reader) (osv.OSVRecord, error) { return NewRecordDebian(r) },
	osv.EcosystemEcho:                       func(r io.Reader) (osv.OSVRecord, error) { return NewRecordEcho(r) },
	osv.EcosystemGHC:                        func(r io.Reader) (osv.OSVRecord, error) { return NewRecordGHC(r) },
	osv.EcosystemGIT:                        func(r io.Reader) (osv.OSVRecord, error) { return NewRecordGIT(r) },
	osv.EcosystemGSD:                        func(r io.Reader) (osv.OSVRecord, error) { return NewRecordGSD(r) },
	osv.EcosystemGeneric:                    func(r io.Reader) (osv.OSVRecord, error) { return NewRecordGeneric(r) },
	osv.EcosystemGitHubActions:              func(r io.Reader) (osv.OSVRecord, error) { return NewRecordGitHubActions(r) },
	osv.EcosystemGo:                         func(r io.Reader) (osv.OSVRecord, error) { return NewRecordGo(r) },
	osv.EcosystemHackage:                    func(r io.Reader) (osv.OSVRecord, error) { return NewRecordHackage(r) },
	osv.EcosystemHex:                        func(r io.Reader) (osv.OSVRecord, error) { return NewRecordHex(r) },
	osv.EcosystemJulia:                      func(r io.Reader) (osv.OSVRecord, error) { return NewRecordJulia(r) },
	osv.EcosystemLinux:                      func(r io.Reader) (osv.OSVRecord, error) { return NewRecordLinux(r) },
	osv.EcosystemMageia:                     func(r io.Reader) (osv.OSVRecord, error) { return NewRecordMageia(r) },
	osv.EcosystemMaven:                      func(r io.Reader) (osv.OSVRecord, error) { return NewRecordMaven(r) },
	osv.EcosystemMinimOS:                    func(r io.Reader) (osv.OSVRecord, error) { return NewRecordMinimOS(r) },
	osv.EcosystemNuGet:                      func(r io.Reader) (osv.OSVRecord, error) { return NewRecordNuGet(r) },
	osv.EcosystemOSSFuzz:                    func(r io.Reader) (osv.OSVRecord, error) { return NewRecordOSSFuzz(r) },
	osv.EcosystemPackagist:                  func(r io.Reader) (osv.OSVRecord, error) { return NewRecordPackagist(r) },
	osv.EcosystemPub:                        func(r io.Reader) (osv.OSVRecord, error) { return NewRecordPub(r) },
	osv.EcosystemPyPI:                       func(r io.Reader) (osv.OSVRecord, error) { return NewRecordPyPI(r) },
	osv.EcosystemRedHat:                     func(r io.Reader) (osv.OSVRecord, error) { return NewRecordRedHat(r) },
	osv.EcosystemRockyLinux:                 func(r io.Reader) (osv.OSVRecord, error) { return NewRecordRockyLinux(r) },
	osv.EcosystemRoot:                       func(r io.Reader) (osv.OSVRecord, error) { return NewRecordRoot(r) },
	osv.EcosystemRubyGems:                   func(r io.Reader) (osv.OSVRecord, error) { return NewRecordRubyGems(r) },
	osv.EcosystemSUSE:                       func(r io.Reader) (osv.OSVRecord, error) { return NewRecordSUSE(r) },
	osv.EcosystemSwiftURL:                   func(r io.Reader) (osv.OSVRecord, error) { return NewRecordSwiftURL(r) },
	osv.EcosystemUVI:                        func(r io.Reader) (osv.OSVRecord, error) { return NewRecordUVI(r) },
	osv.EcosystemUbuntu:                     func(r io.Reader) (osv.OSVRecord, error) { return NewRecordUbuntu(r) },
	osv.EcosystemVSCode:                     func(r io.Reader) (osv.OSVRecord, error) { return NewRecordVSCode(r) },
	osv.EcosystemWolfi:                      func(r io.Reader) (osv.OSVRecord, error) { return NewRecordWolfi(r) },
	osv.EcosystemNpm:                        func(r io.Reader) (osv.OSVRecord, error) { return NewRecordNpm(r) },
	osv.EcosystemOpam:                       func(r io.Reader) (osv.OSVRecord, error) { return NewRecordOpam(r) },
	osv.EcosystemOpenEuler:                  func(r io.Reader) (osv.OSVRecord, error) { return NewRecordOpenEuler(r) },
	osv.EcosystemOpenSUSE:                   func(r io.Reader) (osv.OSVRecord, error) { return NewRecordOpenSUSE(r) },
	osv.EcosystemTuxCare:                    func(r io.Reader) (osv.OSVRecord, error) { return NewRecordTuxCare(r) },
}
