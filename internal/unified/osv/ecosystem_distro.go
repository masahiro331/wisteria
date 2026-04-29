package osv

import (
	"encoding/json"
	"fmt"
	"time"
)

// Distro and other independent ecosystems whose payload shapes are
// unique enough they don't fit into the GHSA cluster. Each ecosystem
// declares its own structs so divergence can land locally.

// --- Android ------------------------------------------------------

type TopAndroid struct{}

func (*TopAndroid) isTopSpecific() {}

type AffectedEcoAndroid struct {
	Fixes           []string                `json:"fixes,omitempty"`
	Severity        string                  `json:"severity,omitempty"`
	SPL             string                  `json:"spl,omitempty"`
	Types           []string                `json:"types,omitempty"`
	VanirSignatures []AndroidVanirSignature `json:"vanir_signatures,omitempty"`
}

func (*AffectedEcoAndroid) isAffectedEcoSpec() {}

type AndroidVanirSignature struct {
	Deprecated               bool               `json:"deprecated"`
	Digest                   AndroidVanirDigest `json:"digest"`
	ExactTargetFileMatchOnly bool               `json:"exact_target_file_match_only,omitempty"`
	ID                       string             `json:"id,omitempty"`
	MatchOnlyVersions        []string           `json:"match_only_versions,omitempty"`
	SignatureType            string             `json:"signature_type,omitempty"`
	SignatureVersion         string             `json:"signature_version,omitempty"`
	Source                   string             `json:"source,omitempty"`
	Target                   AndroidVanirTarget `json:"target,omitzero"`
}

type AndroidVanirDigest struct {
	FunctionHash string   `json:"function_hash,omitempty"`
	Length       int      `json:"length,omitempty"`
	LineHashes   []string `json:"line_hashes,omitempty"`
	Threshold    float64  `json:"threshold,omitempty"`
}

type AndroidVanirTarget struct {
	File               string `json:"file,omitempty"`
	Function           string `json:"function,omitempty"`
	TruncatedPathLevel int    `json:"truncated_path_level,omitempty"`
}

type AffectedDBAndroid struct {
	Source string `json:"source,omitempty"`
}

func (*AffectedDBAndroid) isAffectedDBSpec() {}

type RangeDBAndroid struct{}

func (*RangeDBAndroid) isRangeDBSpec() {}

// --- Bitnami ------------------------------------------------------

type TopBitnami struct {
	CPEs     []string `json:"cpes,omitempty"`
	Severity string   `json:"severity,omitempty"`
}

func (*TopBitnami) isTopSpecific() {}

type AffectedEcoBitnami struct{}

func (*AffectedEcoBitnami) isAffectedEcoSpec() {}

type AffectedDBBitnami struct {
	Source string `json:"source,omitempty"`
}

func (*AffectedDBBitnami) isAffectedDBSpec() {}

type RangeDBBitnami struct{}

func (*RangeDBBitnami) isRangeDBSpec() {}

// --- Debian -------------------------------------------------------

type TopDebian struct{}

func (*TopDebian) isTopSpecific() {}

type AffectedEcoDebian struct {
	Urgency string `json:"urgency,omitempty"`
}

func (*AffectedEcoDebian) isAffectedEcoSpec() {}

type AffectedDBDebian struct {
	Source string `json:"source,omitempty"`
}

func (*AffectedDBDebian) isAffectedDBSpec() {}

type RangeDBDebian struct{}

func (*RangeDBDebian) isRangeDBSpec() {}

// --- GHC ----------------------------------------------------------

type TopGHC struct {
	Home       string `json:"home,omitempty"`
	OSVs       string `json:"osvs,omitempty"`
	Repository string `json:"repository,omitempty"`
}

func (*TopGHC) isTopSpecific() {}

type AffectedEcoGHC struct{}

func (*AffectedEcoGHC) isAffectedEcoSpec() {}

type AffectedDBGHC struct {
	HumanLink string `json:"human_link,omitempty"`
	OSV       string `json:"osv,omitempty"`
	Source    string `json:"source,omitempty"`
}

func (*AffectedDBGHC) isAffectedDBSpec() {}

type RangeDBGHC struct{}

func (*RangeDBGHC) isRangeDBSpec() {}

// --- Hackage ------------------------------------------------------

type TopHackage struct {
	Home       string `json:"home,omitempty"`
	OSVs       string `json:"osvs,omitempty"`
	Repository string `json:"repository,omitempty"`
}

func (*TopHackage) isTopSpecific() {}

type AffectedEcoHackage struct{}

func (*AffectedEcoHackage) isAffectedEcoSpec() {}

type AffectedDBHackage struct {
	HumanLink string `json:"human_link,omitempty"`
	OSV       string `json:"osv,omitempty"`
	Source    string `json:"source,omitempty"`
}

func (*AffectedDBHackage) isAffectedDBSpec() {}

type RangeDBHackage struct{}

func (*RangeDBHackage) isRangeDBSpec() {}

// --- Julia --------------------------------------------------------

type TopJulia struct {
	License string        `json:"license,omitempty"`
	Sources []JuliaSource `json:"sources,omitempty"`
}

func (*TopJulia) isTopSpecific() {}

type JuliaSource struct {
	DatabaseSpecific *JuliaSourceDB `json:"database_specific,omitempty"`
	HTMLURL          string         `json:"html_url,omitempty"`
	ID               string         `json:"id,omitempty"`
	Imported         time.Time      `json:"imported,omitzero"`
	Modified         time.Time      `json:"modified,omitzero"`
	Published        time.Time      `json:"published,omitzero"`
	URL              string         `json:"url,omitempty"`
}

// JuliaSourceDB holds the per-source-record database_specific block
// the Julia importer attaches to NVD imports.
type JuliaSourceDB struct {
	Status string           `json:"status,omitempty"`
	Tags   []JuliaSourceTag `json:"tags,omitempty"`
}

type JuliaSourceTag struct {
	SourceIdentifier string   `json:"sourceIdentifier,omitempty"`
	Tags             []string `json:"tags,omitempty"`
}

type AffectedEcoJulia struct{}

func (*AffectedEcoJulia) isAffectedEcoSpec() {}

type AffectedDBJulia struct {
	Source string `json:"source,omitempty"`
}

func (*AffectedDBJulia) isAffectedDBSpec() {}

type RangeDBJulia struct{}

func (*RangeDBJulia) isRangeDBSpec() {}

// --- Linux --------------------------------------------------------

type TopLinux struct {
	CNAAssigner      string `json:"cna_assigner,omitempty"`
	OSVGeneratedFrom string `json:"osv_generated_from,omitempty"`
}

func (*TopLinux) isTopSpecific() {}

type AffectedEcoLinux struct{}

func (*AffectedEcoLinux) isAffectedEcoSpec() {}

type AffectedDBLinux struct {
	Source          string                  `json:"source,omitempty"`
	VanirSignatures []AndroidVanirSignature `json:"vanir_signatures,omitempty"`
}

func (*AffectedDBLinux) isAffectedDBSpec() {}

type RangeDBLinux struct{}

func (*RangeDBLinux) isRangeDBSpec() {}

// --- Mageia -------------------------------------------------------

type TopMageia struct{}

func (*TopMageia) isTopSpecific() {}

type AffectedEcoMageia struct {
	Section string `json:"section,omitempty"`
}

func (*AffectedEcoMageia) isAffectedEcoSpec() {}

type AffectedDBMageia struct {
	Source string `json:"source,omitempty"`
}

func (*AffectedDBMageia) isAffectedDBSpec() {}

type RangeDBMageia struct{}

func (*RangeDBMageia) isRangeDBSpec() {}

// --- SUSE ---------------------------------------------------------

type TopSUSE struct{}

func (*TopSUSE) isTopSpecific() {}

// AffectedEcoSUSE captures `affected[].ecosystem_specific` for SUSE.
// The `binaries` list is a sequence of single-key objects mapping
// upstream package name → version; the package-name key is dynamic,
// so we model each element as map[string]string and let json decode
// the dynamic key directly.
type AffectedEcoSUSE struct {
	Binaries []map[string]string `json:"binaries,omitempty"`
}

func (*AffectedEcoSUSE) isAffectedEcoSpec() {}

type AffectedDBSUSE struct {
	Source string `json:"source,omitempty"`
}

func (*AffectedDBSUSE) isAffectedDBSpec() {}

type RangeDBSUSE struct{}

func (*RangeDBSUSE) isRangeDBSpec() {}

// --- openSUSE -----------------------------------------------------

type TopOpenSUSE struct{}

func (*TopOpenSUSE) isTopSpecific() {}

type AffectedEcoOpenSUSE struct {
	Binaries []map[string]string `json:"binaries,omitempty"`
}

func (*AffectedEcoOpenSUSE) isAffectedEcoSpec() {}

type AffectedDBOpenSUSE struct {
	Source string `json:"source,omitempty"`
}

func (*AffectedDBOpenSUSE) isAffectedDBSpec() {}

type RangeDBOpenSUSE struct{}

func (*RangeDBOpenSUSE) isRangeDBSpec() {}

// --- Ubuntu -------------------------------------------------------

type TopUbuntu struct{}

func (*TopUbuntu) isTopSpecific() {}

type AffectedEcoUbuntu struct {
	Availability    string         `json:"availability,omitempty"`
	Binaries        []UbuntuBinary `json:"binaries,omitempty"`
	ModuleNameRegex string         `json:"module_name_regex,omitempty"`
	ModuleVersion   string         `json:"module_version,omitempty"`
	PriorityReason  string         `json:"priority_reason,omitempty"`
	UbuntuPriority  string         `json:"ubuntu_priority,omitempty"`
}

func (*AffectedEcoUbuntu) isAffectedEcoSpec() {}

// UbuntuBinary holds either the explicit `{binary_name, binary_version}`
// shape (the standard Ubuntu OSV emitter) or a single-entry dynamic-key
// map mirroring SUSE/openSUSE's binaries layout (used by some USN
// records). Both shapes round-trip verbatim.
type UbuntuBinary struct {
	BinaryName    string
	BinaryVersion string
	DynamicMap    map[string]string
}

func (b UbuntuBinary) MarshalJSON() ([]byte, error) {
	if b.DynamicMap != nil {
		return json.Marshal(b.DynamicMap)
	}
	type tmp struct {
		BinaryName    string `json:"binary_name,omitempty"`
		BinaryVersion string `json:"binary_version,omitempty"`
	}
	return json.Marshal(tmp{BinaryName: b.BinaryName, BinaryVersion: b.BinaryVersion})
}

func (b *UbuntuBinary) UnmarshalJSON(data []byte) error {
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	// Detect the canonical {binary_name, binary_version} shape: exactly
	// those keys, both string, nothing else.
	_, hasName := raw["binary_name"]
	_, hasVersion := raw["binary_version"]
	if hasName && hasVersion && len(raw) <= 2 {
		var t struct {
			BinaryName    string `json:"binary_name,omitempty"`
			BinaryVersion string `json:"binary_version,omitempty"`
		}
		if err := json.Unmarshal(data, &t); err != nil {
			return err
		}
		*b = UbuntuBinary{BinaryName: t.BinaryName, BinaryVersion: t.BinaryVersion}
		return nil
	}
	// Otherwise treat the whole object as a dynamic-key map.
	m := make(map[string]string, len(raw))
	for k, v := range raw {
		s, ok := v.(string)
		if !ok {
			return fmt.Errorf("UbuntuBinary: dynamic-map value for %q is %T, want string", k, v)
		}
		m[k] = s
	}
	*b = UbuntuBinary{DynamicMap: m}
	return nil
}

type AffectedDBUbuntu struct {
	CVEsMap map[string]any `json:"cves_map,omitempty"`
	Source  string         `json:"source,omitempty"`
}

func (*AffectedDBUbuntu) isAffectedDBSpec() {}

type RangeDBUbuntu struct{}

func (*RangeDBUbuntu) isRangeDBSpec() {}

// --- VSCode -------------------------------------------------------

type TopVSCode struct {
	IOCs                     *PyPIIOCs               `json:"iocs,omitempty"`
	MaliciousPackagesOrigins []GHSAMalPackagesOrigin `json:"malicious-packages-origins,omitempty"`
}

func (*TopVSCode) isTopSpecific() {}

type AffectedEcoVSCode struct{}

func (*AffectedEcoVSCode) isAffectedEcoSpec() {}

type AffectedDBVSCode struct {
	Source string `json:"source,omitempty"`
}

func (*AffectedDBVSCode) isAffectedDBSpec() {}

type RangeDBVSCode struct{}

func (*RangeDBVSCode) isRangeDBSpec() {}

// --- opam ---------------------------------------------------------

type TopOpam struct {
	CWE       []string `json:"cwe,omitempty"`
	HumanLink string   `json:"human_link,omitempty"`
	OSV       string   `json:"osv,omitempty"`
}

func (*TopOpam) isTopSpecific() {}

type AffectedEcoOpam struct {
	OpamConstraint string `json:"opam_constraint,omitempty"`
}

func (*AffectedEcoOpam) isAffectedEcoSpec() {}

type AffectedDBOpam struct {
	Source string `json:"source,omitempty"`
}

func (*AffectedDBOpam) isAffectedDBSpec() {}

type RangeDBOpam struct{}

func (*RangeDBOpam) isRangeDBSpec() {}

// --- openEuler ----------------------------------------------------

type TopOpenEuler struct {
	Severity string `json:"severity,omitempty"`
}

func (*TopOpenEuler) isTopSpecific() {}

type AffectedEcoOpenEuler struct {
	AArch64 []string `json:"aarch64,omitempty"`
	Noarch  []string `json:"noarch,omitempty"`
	Src     []string `json:"src,omitempty"`
	X8664   []string `json:"x86_64,omitempty"`
}

func (*AffectedEcoOpenEuler) isAffectedEcoSpec() {}

type AffectedDBOpenEuler struct {
	Source string `json:"source,omitempty"`
}

func (*AffectedDBOpenEuler) isAffectedDBSpec() {}

type RangeDBOpenEuler struct{}

func (*RangeDBOpenEuler) isRangeDBSpec() {}

func init() {
	register("Android", ecosystemDispatch{
		top:    func() TopSpecific { return &TopAndroid{} },
		affEco: func() AffectedEcoSpec { return &AffectedEcoAndroid{} },
		affDB:  func() AffectedDBSpec { return &AffectedDBAndroid{} },
		rngDB:  func() RangeDBSpec { return &RangeDBAndroid{} },
	})
	register("Bitnami", ecosystemDispatch{
		top:    func() TopSpecific { return &TopBitnami{} },
		affEco: func() AffectedEcoSpec { return &AffectedEcoBitnami{} },
		affDB:  func() AffectedDBSpec { return &AffectedDBBitnami{} },
		rngDB:  func() RangeDBSpec { return &RangeDBBitnami{} },
	})
	register("Debian", ecosystemDispatch{
		top:    func() TopSpecific { return &TopDebian{} },
		affEco: func() AffectedEcoSpec { return &AffectedEcoDebian{} },
		affDB:  func() AffectedDBSpec { return &AffectedDBDebian{} },
		rngDB:  func() RangeDBSpec { return &RangeDBDebian{} },
	})
	register("GHC", ecosystemDispatch{
		top:    func() TopSpecific { return &TopGHC{} },
		affEco: func() AffectedEcoSpec { return &AffectedEcoGHC{} },
		affDB:  func() AffectedDBSpec { return &AffectedDBGHC{} },
		rngDB:  func() RangeDBSpec { return &RangeDBGHC{} },
	})
	register("Hackage", ecosystemDispatch{
		top:    func() TopSpecific { return &TopHackage{} },
		affEco: func() AffectedEcoSpec { return &AffectedEcoHackage{} },
		affDB:  func() AffectedDBSpec { return &AffectedDBHackage{} },
		rngDB:  func() RangeDBSpec { return &RangeDBHackage{} },
	})
	register("Julia", ecosystemDispatch{
		top:    func() TopSpecific { return &TopJulia{} },
		affEco: func() AffectedEcoSpec { return &AffectedEcoJulia{} },
		affDB:  func() AffectedDBSpec { return &AffectedDBJulia{} },
		rngDB:  func() RangeDBSpec { return &RangeDBJulia{} },
	})
	register("Linux", ecosystemDispatch{
		top:    func() TopSpecific { return &TopLinux{} },
		affEco: func() AffectedEcoSpec { return &AffectedEcoLinux{} },
		affDB:  func() AffectedDBSpec { return &AffectedDBLinux{} },
		rngDB:  func() RangeDBSpec { return &RangeDBLinux{} },
	})
	register("Mageia", ecosystemDispatch{
		top:    func() TopSpecific { return &TopMageia{} },
		affEco: func() AffectedEcoSpec { return &AffectedEcoMageia{} },
		affDB:  func() AffectedDBSpec { return &AffectedDBMageia{} },
		rngDB:  func() RangeDBSpec { return &RangeDBMageia{} },
	})
	register("SUSE", ecosystemDispatch{
		top:    func() TopSpecific { return &TopSUSE{} },
		affEco: func() AffectedEcoSpec { return &AffectedEcoSUSE{} },
		affDB:  func() AffectedDBSpec { return &AffectedDBSUSE{} },
		rngDB:  func() RangeDBSpec { return &RangeDBSUSE{} },
	})
	register("openSUSE", ecosystemDispatch{
		top:    func() TopSpecific { return &TopOpenSUSE{} },
		affEco: func() AffectedEcoSpec { return &AffectedEcoOpenSUSE{} },
		affDB:  func() AffectedDBSpec { return &AffectedDBOpenSUSE{} },
		rngDB:  func() RangeDBSpec { return &RangeDBOpenSUSE{} },
	})
	register("Ubuntu", ecosystemDispatch{
		top:    func() TopSpecific { return &TopUbuntu{} },
		affEco: func() AffectedEcoSpec { return &AffectedEcoUbuntu{} },
		affDB:  func() AffectedDBSpec { return &AffectedDBUbuntu{} },
		rngDB:  func() RangeDBSpec { return &RangeDBUbuntu{} },
	})
	register("VSCode", ecosystemDispatch{
		top:    func() TopSpecific { return &TopVSCode{} },
		affEco: func() AffectedEcoSpec { return &AffectedEcoVSCode{} },
		affDB:  func() AffectedDBSpec { return &AffectedDBVSCode{} },
		rngDB:  func() RangeDBSpec { return &RangeDBVSCode{} },
	})
	register("opam", ecosystemDispatch{
		top:    func() TopSpecific { return &TopOpam{} },
		affEco: func() AffectedEcoSpec { return &AffectedEcoOpam{} },
		affDB:  func() AffectedDBSpec { return &AffectedDBOpam{} },
		rngDB:  func() RangeDBSpec { return &RangeDBOpam{} },
	})
	register("openEuler", ecosystemDispatch{
		top:    func() TopSpecific { return &TopOpenEuler{} },
		affEco: func() AffectedEcoSpec { return &AffectedEcoOpenEuler{} },
		affDB:  func() AffectedDBSpec { return &AffectedDBOpenEuler{} },
		rngDB:  func() RangeDBSpec { return &RangeDBOpenEuler{} },
	})
}
