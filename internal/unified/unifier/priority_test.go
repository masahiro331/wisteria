package unifier

import "testing"

// TestSourceConstants pins each exported priority tag to its on-the-wire
// string value. Downstream callers (writer routing, debug commands,
// future CLI flags) read these values via the constants; if the literal
// drifts the merge / routing contract silently breaks, so this test
// fixes the value here.
//
// Membership is the full set of OSV ecosystems the upstream OSV catalog
// publishes plus CVE5. Whether a given tag participates in the §8.1
// priority array is a separate decision (TestSourcePriorityDraft); this
// test only fixes the const value.
func TestSourceConstants(t *testing.T) {
	cases := []struct {
		name string
		got  string
		want string
	}{
		{"SourceCVEMitre", SourceCVEMitre, "cve.mitre"},
		{"SourceOSVAlmaLinux", SourceOSVAlmaLinux, "osv.AlmaLinux"},
		{"SourceOSVAlpaquita", SourceOSVAlpaquita, "osv.Alpaquita"},
		{"SourceOSVAlpine", SourceOSVAlpine, "osv.Alpine"},
		{"SourceOSVAndroid", SourceOSVAndroid, "osv.Android"},
		{"SourceOSVAzureLinux", SourceOSVAzureLinux, "osv.Azure_Linux"},
		{"SourceOSVBellSoftHardenedContainers", SourceOSVBellSoftHardenedContainers, "osv.BellSoft_Hardened_Containers"},
		{"SourceOSVBitnami", SourceOSVBitnami, "osv.Bitnami"},
		{"SourceOSVChainguard", SourceOSVChainguard, "osv.Chainguard"},
		{"SourceOSVCleanStart", SourceOSVCleanStart, "osv.CleanStart"},
		{"SourceOSVCRAN", SourceOSVCRAN, "osv.CRAN"},
		{"SourceOSVCratesIO", SourceOSVCratesIO, "osv.crates.io"},
		{"SourceOSVDebian", SourceOSVDebian, "osv.Debian"},
		{"SourceOSVEcho", SourceOSVEcho, "osv.Echo"},
		{"SourceOSVGeneric", SourceOSVGeneric, "osv.Generic"},
		{"SourceOSVGHC", SourceOSVGHC, "osv.GHC"},
		{"SourceOSVGIT", SourceOSVGIT, "osv.GIT"},
		{"SourceOSVGitHubActions", SourceOSVGitHubActions, "osv.GitHub_Actions"},
		{"SourceOSVGitHubReviewed", SourceOSVGitHubReviewed, "osv.GitHub_Reviewed"},
		{"SourceOSVGo", SourceOSVGo, "osv.Go"},
		{"SourceOSVGSD", SourceOSVGSD, "osv.GSD"},
		{"SourceOSVHackage", SourceOSVHackage, "osv.Hackage"},
		{"SourceOSVHex", SourceOSVHex, "osv.Hex"},
		{"SourceOSVJulia", SourceOSVJulia, "osv.Julia"},
		{"SourceOSVLinux", SourceOSVLinux, "osv.Linux"},
		{"SourceOSVMageia", SourceOSVMageia, "osv.Mageia"},
		{"SourceOSVMaven", SourceOSVMaven, "osv.Maven"},
		{"SourceOSVMinimOS", SourceOSVMinimOS, "osv.MinimOS"},
		{"SourceOSVnpm", SourceOSVnpm, "osv.npm"},
		{"SourceOSVNuGet", SourceOSVNuGet, "osv.NuGet"},
		{"SourceOSVopam", SourceOSVopam, "osv.opam"},
		{"SourceOSVopenEuler", SourceOSVopenEuler, "osv.openEuler"},
		{"SourceOSVopenSUSE", SourceOSVopenSUSE, "osv.openSUSE"},
		{"SourceOSVOSSFuzz", SourceOSVOSSFuzz, "osv.OSS-Fuzz"},
		{"SourceOSVPackagist", SourceOSVPackagist, "osv.Packagist"},
		{"SourceOSVPub", SourceOSVPub, "osv.Pub"},
		{"SourceOSVPyPI", SourceOSVPyPI, "osv.PyPI"},
		{"SourceOSVRedHat", SourceOSVRedHat, "osv.Red_Hat"},
		{"SourceOSVRockyLinux", SourceOSVRockyLinux, "osv.Rocky_Linux"},
		{"SourceOSVRoot", SourceOSVRoot, "osv.Root"},
		{"SourceOSVRubyGems", SourceOSVRubyGems, "osv.RubyGems"},
		{"SourceOSVSUSE", SourceOSVSUSE, "osv.SUSE"},
		{"SourceOSVSwiftURL", SourceOSVSwiftURL, "osv.SwiftURL"},
		{"SourceOSVUbuntu", SourceOSVUbuntu, "osv.Ubuntu"},
		{"SourceOSVUVI", SourceOSVUVI, "osv.UVI"},
		{"SourceOSVVSCode", SourceOSVVSCode, "osv.VSCode"},
		{"SourceOSVWolfi", SourceOSVWolfi, "osv.Wolfi"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got != tc.want {
				t.Errorf("%s = %q, want %q", tc.name, tc.got, tc.want)
			}
		})
	}
}

// TestSourcePriorityDraft pins the §8.1 draft array. Membership and
// order are explicitly draft until "Vendor priority array final members"
// (docs/ROADMAP.md Phase 1) is decided. Once finalized, expand `want` to
// reference the additional Source* constants in their decided order.
func TestSourcePriorityDraft(t *testing.T) {
	want := []string{
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
	if len(sourcePriority) != len(want) {
		t.Fatalf("sourcePriority length = %d, want %d", len(sourcePriority), len(want))
	}
	for i, s := range want {
		if sourcePriority[i] != s {
			t.Errorf("sourcePriority[%d] = %q, want %q", i, sourcePriority[i], s)
		}
	}
}
