package unifier

// Source* are the cross-field source tags used by §8.1. Tag format is
// "<SourceKind>.<ecosystem>"; the ecosystem segment is the
// already-normalized IndexEntry.Source value (walker replaces spaces
// with "_"), so multi-word ecosystems appear here as e.g. "Red_Hat".
// CVE5 is a single fixed tag because every CVE5 file is treated as the
// CNA-of-record (CNA and ADP share the tag; ADP-vs-CNA is distinguished
// at the Provenance.ID level via the "#adp:<shortName>" suffix).
//
// Membership is the full set of OSV ecosystems the upstream OSV catalog
// publishes plus CVE5. Whether a given tag participates in the §8.1
// priority array (sourcePriority below) is a separate decision pending
// real-data observation; the constants exist so external callers
// (debug commands, future CLI flags, sibling pipeline stages) can refer
// to a tag by name regardless of its priority membership.
const (
	SourceCVEMitre = "cve.mitre"

	SourceOSVAlmaLinux                  = "osv.AlmaLinux"
	SourceOSVAlpaquita                  = "osv.Alpaquita"
	SourceOSVAlpine                     = "osv.Alpine"
	SourceOSVAndroid                    = "osv.Android"
	SourceOSVAzureLinux                 = "osv.Azure_Linux"
	SourceOSVBellSoftHardenedContainers = "osv.BellSoft_Hardened_Containers"
	SourceOSVBitnami                    = "osv.Bitnami"
	SourceOSVChainguard                 = "osv.Chainguard"
	SourceOSVCleanStart                 = "osv.CleanStart"
	SourceOSVCRAN                       = "osv.CRAN"
	SourceOSVCratesIO                   = "osv.crates.io"
	SourceOSVDebian                     = "osv.Debian"
	SourceOSVEcho                       = "osv.Echo"
	SourceOSVGeneric                    = "osv.Generic"
	SourceOSVGHC                        = "osv.GHC"
	SourceOSVGIT                        = "osv.GIT"
	SourceOSVGitHubActions              = "osv.GitHub_Actions"
	SourceOSVGitHubReviewed             = "osv.GitHub_Reviewed"
	SourceOSVGo                         = "osv.Go"
	SourceOSVGSD                        = "osv.GSD"
	SourceOSVHackage                    = "osv.Hackage"
	SourceOSVHex                        = "osv.Hex"
	SourceOSVJulia                      = "osv.Julia"
	SourceOSVLinux                      = "osv.Linux"
	SourceOSVMageia                     = "osv.Mageia"
	SourceOSVMaven                      = "osv.Maven"
	SourceOSVMinimOS                    = "osv.MinimOS"
	SourceOSVnpm                        = "osv.npm"
	SourceOSVNuGet                      = "osv.NuGet"
	SourceOSVopam                       = "osv.opam"
	SourceOSVopenEuler                  = "osv.openEuler"
	SourceOSVopenSUSE                   = "osv.openSUSE"
	SourceOSVOSSFuzz                    = "osv.OSS-Fuzz"
	SourceOSVPackagist                  = "osv.Packagist"
	SourceOSVPub                        = "osv.Pub"
	SourceOSVPyPI                       = "osv.PyPI"
	SourceOSVRedHat                     = "osv.Red_Hat"
	SourceOSVRockyLinux                 = "osv.Rocky_Linux"
	SourceOSVRoot                       = "osv.Root"
	SourceOSVRubyGems                   = "osv.RubyGems"
	SourceOSVSUSE                       = "osv.SUSE"
	SourceOSVSwiftURL                   = "osv.SwiftURL"
	SourceOSVUbuntu                     = "osv.Ubuntu"
	SourceOSVUVI                        = "osv.UVI"
	SourceOSVVSCode                     = "osv.VSCode"
	SourceOSVWolfi                      = "osv.Wolfi"
)

// sourcePriority is the draft cross-field vendor ordering from §8.1.
// Final membership is pinned once enough real-data observations are in
// (see docs/ROADMAP.md Phase 1 "Vendor priority array final members");
// until then, sources missing from this list fall through to
// defaultRank (sorted last) even though every OSV ecosystem has a
// Source* constant defined above.
var sourcePriority = []string{
	SourceCVEMitre,
	SourceOSVRedHat,
	SourceOSVAlmaLinux,
	SourceOSVRockyLinux,
	SourceOSVSUSE,
	SourceOSVUbuntu,
	SourceOSVDebian,
	SourceOSVAlpine,
	SourceOSVGitHubReviewed,
	SourceOSVPyPI,
	SourceOSVnpm,
	SourceOSVGo,
}

// PriorityRank returns the position of source in sourcePriority. Sources
// not in the list rank after every listed source (len(sourcePriority)),
// which keeps unranked entries at the tail without sentinel constants.
// Lower is higher priority. Used by sibling packages (e.g. writer) to pick
// a "primary" Provenance among many.
func PriorityRank(source string) int {
	for i, s := range sourcePriority {
		if s == source {
			return i
		}
	}
	return len(sourcePriority)
}
