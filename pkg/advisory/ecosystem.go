package advisory

// Ecosystem identifies an OSV package ecosystem the way the OSV data
// spells it in `affected[].package.ecosystem` — the exact string a
// db.Driver.FindByPackage lookup keys on. The constants below cover
// every ecosystem the pipeline ingests (mirroring the internal OSV
// parser's enum; a test cross-checks the two lists).
//
// OSV also publishes release-qualified variants ("Alpine:v3.17",
// "Debian:12"); build those with WithSuffix instead of hand-writing
// the colon form.
type Ecosystem string

const (
	EcosystemAlmaLinux                  Ecosystem = "AlmaLinux"
	EcosystemAlpaquita                  Ecosystem = "Alpaquita"
	EcosystemAlpine                     Ecosystem = "Alpine"
	EcosystemAndroid                    Ecosystem = "Android"
	EcosystemAzureLinux                 Ecosystem = "Azure Linux"
	EcosystemBellSoftHardenedContainers Ecosystem = "BellSoft Hardened Containers"
	EcosystemBitnami                    Ecosystem = "Bitnami"
	EcosystemCRAN                       Ecosystem = "CRAN"
	EcosystemChainguard                 Ecosystem = "Chainguard"
	EcosystemCleanStart                 Ecosystem = "CleanStart"
	EcosystemCratesIO                   Ecosystem = "crates.io"
	EcosystemDebian                     Ecosystem = "Debian"
	EcosystemEcho                       Ecosystem = "Echo"
	EcosystemGHC                        Ecosystem = "GHC"
	EcosystemGIT                        Ecosystem = "GIT"
	EcosystemGSD                        Ecosystem = "GSD"
	EcosystemGeneric                    Ecosystem = "Generic"
	EcosystemGitHubActions              Ecosystem = "GitHub Actions"
	EcosystemGo                         Ecosystem = "Go"
	EcosystemHackage                    Ecosystem = "Hackage"
	EcosystemHex                        Ecosystem = "Hex"
	EcosystemJulia                      Ecosystem = "Julia"
	EcosystemLinux                      Ecosystem = "Linux"
	EcosystemMageia                     Ecosystem = "Mageia"
	EcosystemMaven                      Ecosystem = "Maven"
	EcosystemMinimOS                    Ecosystem = "MinimOS"
	EcosystemNuGet                      Ecosystem = "NuGet"
	EcosystemOSSFuzz                    Ecosystem = "OSS-Fuzz"
	EcosystemPackagist                  Ecosystem = "Packagist"
	EcosystemPub                        Ecosystem = "Pub"
	EcosystemPyPI                       Ecosystem = "PyPI"
	EcosystemRedHat                     Ecosystem = "Red Hat"
	EcosystemRockyLinux                 Ecosystem = "Rocky Linux"
	EcosystemRoot                       Ecosystem = "Root"
	EcosystemRubyGems                   Ecosystem = "RubyGems"
	EcosystemSUSE                       Ecosystem = "SUSE"
	EcosystemSwiftURL                   Ecosystem = "SwiftURL"
	EcosystemUVI                        Ecosystem = "UVI"
	EcosystemUbuntu                     Ecosystem = "Ubuntu"
	EcosystemVSCode                     Ecosystem = "VSCode"
	EcosystemWolfi                      Ecosystem = "Wolfi"
	EcosystemNpm                        Ecosystem = "npm"
	EcosystemOpam                       Ecosystem = "opam"
	EcosystemOpenEuler                  Ecosystem = "openEuler"
	EcosystemOpenSUSE                   Ecosystem = "openSUSE"
	EcosystemTuxCare                    Ecosystem = "TuxCare"
)

// ecosystems is the canonical list backing Ecosystems(). Keep it in
// sync with the constant block above; the advisory package test
// cross-checks it against the internal OSV parser's enum.
var ecosystems = []Ecosystem{
	EcosystemAlmaLinux,
	EcosystemAlpaquita,
	EcosystemAlpine,
	EcosystemAndroid,
	EcosystemAzureLinux,
	EcosystemBellSoftHardenedContainers,
	EcosystemBitnami,
	EcosystemCRAN,
	EcosystemChainguard,
	EcosystemCleanStart,
	EcosystemCratesIO,
	EcosystemDebian,
	EcosystemEcho,
	EcosystemGHC,
	EcosystemGIT,
	EcosystemGSD,
	EcosystemGeneric,
	EcosystemGitHubActions,
	EcosystemGo,
	EcosystemHackage,
	EcosystemHex,
	EcosystemJulia,
	EcosystemLinux,
	EcosystemMageia,
	EcosystemMaven,
	EcosystemMinimOS,
	EcosystemNuGet,
	EcosystemOSSFuzz,
	EcosystemPackagist,
	EcosystemPub,
	EcosystemPyPI,
	EcosystemRedHat,
	EcosystemRockyLinux,
	EcosystemRoot,
	EcosystemRubyGems,
	EcosystemSUSE,
	EcosystemSwiftURL,
	EcosystemUVI,
	EcosystemUbuntu,
	EcosystemVSCode,
	EcosystemWolfi,
	EcosystemNpm,
	EcosystemOpam,
	EcosystemOpenEuler,
	EcosystemOpenSUSE,
	EcosystemTuxCare,
}

// Ecosystems returns every known base ecosystem (no release suffixes),
// in the order of the constant block. The slice is a copy — callers
// may mutate it freely.
func Ecosystems() []Ecosystem {
	out := make([]Ecosystem, len(ecosystems))
	copy(out, ecosystems)
	return out
}

// WithSuffix returns the release-qualified form of e ("Alpine" +
// "v3.17" → "Alpine:v3.17") that OSV uses for per-release package
// keys. An empty suffix returns e unchanged.
func (e Ecosystem) WithSuffix(suffix string) Ecosystem {
	if suffix == "" {
		return e
	}
	return e + ":" + Ecosystem(suffix)
}
