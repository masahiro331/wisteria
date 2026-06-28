package ecosystem

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/masahiro331/wisteria/internal/unified/osv"
)

// Distro and other independent ecosystems whose payload shapes are
// unique enough they don't fit into the GHSA cluster.

// ============================================================
// Android
// ============================================================

type RecordAndroid struct {
	osv.Record
	Affected         []AffectedAndroid `json:"affected,omitempty"`
	DatabaseSpecific TopAndroid        `json:"database_specific,omitzero"`
}

func (r *RecordAndroid) Base() *osv.Record  { return &r.Record }
func (r *RecordAndroid) AffectedAny() []any { return affectedAny(r.Affected) }

type AffectedAndroid struct {
	osv.AffectedBase
	Ranges            []RangeAndroid     `json:"ranges,omitempty"`
	EcosystemSpecific AffectedEcoAndroid `json:"ecosystem_specific,omitzero"`
	DatabaseSpecific  AffectedDBAndroid  `json:"database_specific,omitzero"`
}

type RangeAndroid struct{ osv.RangeBase }

type TopAndroid struct{}

func (TopAndroid) IsZero() bool { return true }

type AffectedEcoAndroid struct {
	Fixes           []string                `json:"fixes,omitempty"`
	Severity        string                  `json:"severity,omitempty"`
	SPL             string                  `json:"spl,omitempty"`
	Types           []string                `json:"types,omitempty"`
	VanirSignatures []AndroidVanirSignature `json:"vanir_signatures,omitempty"`
}

func (a AffectedEcoAndroid) IsZero() bool {
	return a.Fixes == nil && a.Severity == "" && a.SPL == "" &&
		a.Types == nil && a.VanirSignatures == nil
}

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

func (t AndroidVanirTarget) IsZero() bool {
	return t == AndroidVanirTarget{}
}

type AffectedDBAndroid struct {
	Source string `json:"source,omitempty"`
}

func (a AffectedDBAndroid) IsZero() bool { return a == AffectedDBAndroid{} }

func NewRecordAndroid(r io.Reader) (*RecordAndroid, error) {
	var rec RecordAndroid
	if err := json.NewDecoder(r).Decode(&rec); err != nil {
		return nil, fmt.Errorf("osv: parse Android: %w", err)
	}
	rec.Ecosystem = osv.EcosystemAndroid
	return &rec, nil
}

// ============================================================
// Bitnami
// ============================================================

type RecordBitnami struct {
	osv.Record
	Affected         []AffectedBitnami `json:"affected,omitempty"`
	DatabaseSpecific TopBitnami        `json:"database_specific,omitzero"`
}

func (r *RecordBitnami) Base() *osv.Record  { return &r.Record }
func (r *RecordBitnami) AffectedAny() []any { return affectedAny(r.Affected) }

type AffectedBitnami struct {
	osv.AffectedBase
	Ranges            []RangeBitnami     `json:"ranges,omitempty"`
	EcosystemSpecific AffectedEcoBitnami `json:"ecosystem_specific,omitzero"`
	DatabaseSpecific  AffectedDBBitnami  `json:"database_specific,omitzero"`
}

type RangeBitnami struct{ osv.RangeBase }

type TopBitnami struct {
	CPEs     []string `json:"cpes,omitempty"`
	Severity string   `json:"severity,omitempty"`
}

func (t TopBitnami) IsZero() bool { return t.CPEs == nil && t.Severity == "" }

type AffectedEcoBitnami struct{}

func (AffectedEcoBitnami) IsZero() bool { return true }

type AffectedDBBitnami struct {
	Source string `json:"source,omitempty"`
}

func (a AffectedDBBitnami) IsZero() bool { return a == AffectedDBBitnami{} }

func NewRecordBitnami(r io.Reader) (*RecordBitnami, error) {
	var rec RecordBitnami
	if err := json.NewDecoder(r).Decode(&rec); err != nil {
		return nil, fmt.Errorf("osv: parse Bitnami: %w", err)
	}
	rec.Ecosystem = osv.EcosystemBitnami
	return &rec, nil
}

// ============================================================
// Debian
// ============================================================

type RecordDebian struct {
	osv.Record
	Affected         []AffectedDebian `json:"affected,omitempty"`
	DatabaseSpecific TopDebian        `json:"database_specific,omitzero"`
}

func (r *RecordDebian) Base() *osv.Record  { return &r.Record }
func (r *RecordDebian) AffectedAny() []any { return affectedAny(r.Affected) }

type AffectedDebian struct {
	osv.AffectedBase
	Ranges            []RangeDebian     `json:"ranges,omitempty"`
	EcosystemSpecific AffectedEcoDebian `json:"ecosystem_specific,omitzero"`
	DatabaseSpecific  AffectedDBDebian  `json:"database_specific,omitzero"`
}

type RangeDebian struct{ osv.RangeBase }

type TopDebian struct{}

func (TopDebian) IsZero() bool { return true }

type AffectedEcoDebian struct {
	Urgency string `json:"urgency,omitempty"`
}

func (a AffectedEcoDebian) IsZero() bool { return a == AffectedEcoDebian{} }

type AffectedDBDebian struct {
	Source string `json:"source,omitempty"`
}

func (a AffectedDBDebian) IsZero() bool { return a == AffectedDBDebian{} }

func NewRecordDebian(r io.Reader) (*RecordDebian, error) {
	var rec RecordDebian
	if err := json.NewDecoder(r).Decode(&rec); err != nil {
		return nil, fmt.Errorf("osv: parse Debian: %w", err)
	}
	rec.Ecosystem = osv.EcosystemDebian
	return &rec, nil
}

// ============================================================
// GHC
// ============================================================

type RecordGHC struct {
	osv.Record
	Affected         []AffectedGHC `json:"affected,omitempty"`
	DatabaseSpecific TopGHC        `json:"database_specific,omitzero"`
}

func (r *RecordGHC) Base() *osv.Record  { return &r.Record }
func (r *RecordGHC) AffectedAny() []any { return affectedAny(r.Affected) }

type AffectedGHC struct {
	osv.AffectedBase
	Ranges            []RangeGHC     `json:"ranges,omitempty"`
	EcosystemSpecific AffectedEcoGHC `json:"ecosystem_specific,omitzero"`
	DatabaseSpecific  AffectedDBGHC  `json:"database_specific,omitzero"`
}

type RangeGHC struct{ osv.RangeBase }

type TopGHC struct {
	Home       string `json:"home,omitempty"`
	OSVs       string `json:"osvs,omitempty"`
	Repository string `json:"repository,omitempty"`
}

func (t TopGHC) IsZero() bool { return t == TopGHC{} }

type AffectedEcoGHC struct{}

func (AffectedEcoGHC) IsZero() bool { return true }

type AffectedDBGHC struct {
	HumanLink string `json:"human_link,omitempty"`
	OSV       string `json:"osv,omitempty"`
	Source    string `json:"source,omitempty"`
}

func (a AffectedDBGHC) IsZero() bool { return a == AffectedDBGHC{} }

func NewRecordGHC(r io.Reader) (*RecordGHC, error) {
	var rec RecordGHC
	if err := json.NewDecoder(r).Decode(&rec); err != nil {
		return nil, fmt.Errorf("osv: parse GHC: %w", err)
	}
	rec.Ecosystem = osv.EcosystemGHC
	return &rec, nil
}

// ============================================================
// Hackage
// ============================================================

type RecordHackage struct {
	osv.Record
	Affected         []AffectedHackage `json:"affected,omitempty"`
	DatabaseSpecific TopHackage        `json:"database_specific,omitzero"`
}

func (r *RecordHackage) Base() *osv.Record  { return &r.Record }
func (r *RecordHackage) AffectedAny() []any { return affectedAny(r.Affected) }

type AffectedHackage struct {
	osv.AffectedBase
	Ranges            []RangeHackage     `json:"ranges,omitempty"`
	EcosystemSpecific AffectedEcoHackage `json:"ecosystem_specific,omitzero"`
	DatabaseSpecific  AffectedDBHackage  `json:"database_specific,omitzero"`
}

type RangeHackage struct{ osv.RangeBase }

type TopHackage struct {
	Home       string `json:"home,omitempty"`
	OSVs       string `json:"osvs,omitempty"`
	Repository string `json:"repository,omitempty"`
}

func (t TopHackage) IsZero() bool { return t == TopHackage{} }

type AffectedEcoHackage struct{}

func (AffectedEcoHackage) IsZero() bool { return true }

type AffectedDBHackage struct {
	HumanLink string `json:"human_link,omitempty"`
	OSV       string `json:"osv,omitempty"`
	Source    string `json:"source,omitempty"`
}

func (a AffectedDBHackage) IsZero() bool { return a == AffectedDBHackage{} }

func NewRecordHackage(r io.Reader) (*RecordHackage, error) {
	var rec RecordHackage
	if err := json.NewDecoder(r).Decode(&rec); err != nil {
		return nil, fmt.Errorf("osv: parse Hackage: %w", err)
	}
	rec.Ecosystem = osv.EcosystemHackage
	return &rec, nil
}

// ============================================================
// Julia
// ============================================================

type RecordJulia struct {
	osv.Record
	Affected         []AffectedJulia `json:"affected,omitempty"`
	DatabaseSpecific TopJulia        `json:"database_specific,omitzero"`
}

func (r *RecordJulia) Base() *osv.Record  { return &r.Record }
func (r *RecordJulia) AffectedAny() []any { return affectedAny(r.Affected) }

type AffectedJulia struct {
	osv.AffectedBase
	Ranges            []RangeJulia     `json:"ranges,omitempty"`
	EcosystemSpecific AffectedEcoJulia `json:"ecosystem_specific,omitzero"`
	DatabaseSpecific  AffectedDBJulia  `json:"database_specific,omitzero"`
}

type RangeJulia struct{ osv.RangeBase }

type TopJulia struct {
	License string        `json:"license,omitempty"`
	Sources []JuliaSource `json:"sources,omitempty"`
}

func (t TopJulia) IsZero() bool { return t.License == "" && t.Sources == nil }

type JuliaSource struct {
	DatabaseSpecific *JuliaSourceDB `json:"database_specific,omitempty"`
	HTMLURL          string         `json:"html_url,omitempty"`
	ID               string         `json:"id,omitempty"`
	Imported         time.Time      `json:"imported,omitzero"`
	Modified         time.Time      `json:"modified,omitzero"`
	Published        time.Time      `json:"published,omitzero"`
	URL              string         `json:"url,omitempty"`
}

type JuliaSourceDB struct {
	Status string           `json:"status,omitempty"`
	Tags   []JuliaSourceTag `json:"tags,omitempty"`
}

type JuliaSourceTag struct {
	SourceIdentifier string   `json:"sourceIdentifier,omitempty"`
	Tags             []string `json:"tags,omitempty"`
}

type AffectedEcoJulia struct{}

func (AffectedEcoJulia) IsZero() bool { return true }

type AffectedDBJulia struct {
	Source string `json:"source,omitempty"`
}

func (a AffectedDBJulia) IsZero() bool { return a == AffectedDBJulia{} }

func NewRecordJulia(r io.Reader) (*RecordJulia, error) {
	var rec RecordJulia
	if err := json.NewDecoder(r).Decode(&rec); err != nil {
		return nil, fmt.Errorf("osv: parse Julia: %w", err)
	}
	rec.Ecosystem = osv.EcosystemJulia
	return &rec, nil
}

// ============================================================
// Linux
// ============================================================

type RecordLinux struct {
	osv.Record
	Affected         []AffectedLinux `json:"affected,omitempty"`
	DatabaseSpecific TopLinux        `json:"database_specific,omitzero"`
}

func (r *RecordLinux) Base() *osv.Record  { return &r.Record }
func (r *RecordLinux) AffectedAny() []any { return affectedAny(r.Affected) }

type AffectedLinux struct {
	osv.AffectedBase
	Ranges            []RangeLinux     `json:"ranges,omitempty"`
	EcosystemSpecific AffectedEcoLinux `json:"ecosystem_specific,omitzero"`
	DatabaseSpecific  AffectedDBLinux  `json:"database_specific,omitzero"`
}

type RangeLinux struct{ osv.RangeBase }

type TopLinux struct {
	CNAAssigner      string `json:"cna_assigner,omitempty"`
	OSVGeneratedFrom string `json:"osv_generated_from,omitempty"`
}

func (t TopLinux) IsZero() bool { return t == TopLinux{} }

type AffectedEcoLinux struct{}

func (AffectedEcoLinux) IsZero() bool { return true }

// AffectedDBLinux carries the Vanir signatures Linux attaches to its
// per-affected payload (same shape as Android Vanir signatures so we
// reuse the type — Linux and Android share Google's importer).
type AffectedDBLinux struct {
	Source          string                  `json:"source,omitempty"`
	VanirSignatures []AndroidVanirSignature `json:"vanir_signatures,omitempty"`
}

func (a AffectedDBLinux) IsZero() bool {
	return a.Source == "" && a.VanirSignatures == nil
}

func NewRecordLinux(r io.Reader) (*RecordLinux, error) {
	var rec RecordLinux
	if err := json.NewDecoder(r).Decode(&rec); err != nil {
		return nil, fmt.Errorf("osv: parse Linux: %w", err)
	}
	rec.Ecosystem = osv.EcosystemLinux
	return &rec, nil
}

// ============================================================
// Mageia
// ============================================================

type RecordMageia struct {
	osv.Record
	Affected         []AffectedMageia `json:"affected,omitempty"`
	DatabaseSpecific TopMageia        `json:"database_specific,omitzero"`
}

func (r *RecordMageia) Base() *osv.Record  { return &r.Record }
func (r *RecordMageia) AffectedAny() []any { return affectedAny(r.Affected) }

type AffectedMageia struct {
	osv.AffectedBase
	Ranges            []RangeMageia     `json:"ranges,omitempty"`
	EcosystemSpecific AffectedEcoMageia `json:"ecosystem_specific,omitzero"`
	DatabaseSpecific  AffectedDBMageia  `json:"database_specific,omitzero"`
}

type RangeMageia struct{ osv.RangeBase }

type TopMageia struct{}

func (TopMageia) IsZero() bool { return true }

type AffectedEcoMageia struct {
	Section string `json:"section,omitempty"`
}

func (a AffectedEcoMageia) IsZero() bool { return a == AffectedEcoMageia{} }

type AffectedDBMageia struct {
	Source string `json:"source,omitempty"`
}

func (a AffectedDBMageia) IsZero() bool { return a == AffectedDBMageia{} }

func NewRecordMageia(r io.Reader) (*RecordMageia, error) {
	var rec RecordMageia
	if err := json.NewDecoder(r).Decode(&rec); err != nil {
		return nil, fmt.Errorf("osv: parse Mageia: %w", err)
	}
	rec.Ecosystem = osv.EcosystemMageia
	return &rec, nil
}

// ============================================================
// SUSE
// ============================================================

type RecordSUSE struct {
	osv.Record
	Affected         []AffectedSUSE `json:"affected,omitempty"`
	DatabaseSpecific TopSUSE        `json:"database_specific,omitzero"`
}

func (r *RecordSUSE) Base() *osv.Record  { return &r.Record }
func (r *RecordSUSE) AffectedAny() []any { return affectedAny(r.Affected) }

type AffectedSUSE struct {
	osv.AffectedBase
	Ranges            []RangeSUSE     `json:"ranges,omitempty"`
	EcosystemSpecific AffectedEcoSUSE `json:"ecosystem_specific,omitzero"`
	DatabaseSpecific  AffectedDBSUSE  `json:"database_specific,omitzero"`
}

type RangeSUSE struct{ osv.RangeBase }

type TopSUSE struct{}

func (TopSUSE) IsZero() bool { return true }

// AffectedEcoSUSE captures `affected[].ecosystem_specific` for SUSE.
// The `binaries` list is a sequence of single-key objects mapping
// upstream package name → version; the package-name key is dynamic,
// so each element is map[string]string.
type AffectedEcoSUSE struct {
	Binaries []map[string]string `json:"binaries,omitempty"`
}

func (a AffectedEcoSUSE) IsZero() bool { return a.Binaries == nil }

type AffectedDBSUSE struct {
	Source string `json:"source,omitempty"`
}

func (a AffectedDBSUSE) IsZero() bool { return a == AffectedDBSUSE{} }

func NewRecordSUSE(r io.Reader) (*RecordSUSE, error) {
	var rec RecordSUSE
	if err := json.NewDecoder(r).Decode(&rec); err != nil {
		return nil, fmt.Errorf("osv: parse SUSE: %w", err)
	}
	rec.Ecosystem = osv.EcosystemSUSE
	return &rec, nil
}

// ============================================================
// openSUSE
// ============================================================

type RecordOpenSUSE struct {
	osv.Record
	Affected         []AffectedOpenSUSE `json:"affected,omitempty"`
	DatabaseSpecific TopOpenSUSE        `json:"database_specific,omitzero"`
}

func (r *RecordOpenSUSE) Base() *osv.Record  { return &r.Record }
func (r *RecordOpenSUSE) AffectedAny() []any { return affectedAny(r.Affected) }

type AffectedOpenSUSE struct {
	osv.AffectedBase
	Ranges            []RangeOpenSUSE     `json:"ranges,omitempty"`
	EcosystemSpecific AffectedEcoOpenSUSE `json:"ecosystem_specific,omitzero"`
	DatabaseSpecific  AffectedDBOpenSUSE  `json:"database_specific,omitzero"`
}

type RangeOpenSUSE struct{ osv.RangeBase }

type TopOpenSUSE struct{}

func (TopOpenSUSE) IsZero() bool { return true }

type AffectedEcoOpenSUSE struct {
	Binaries []map[string]string `json:"binaries,omitempty"`
}

func (a AffectedEcoOpenSUSE) IsZero() bool { return a.Binaries == nil }

type AffectedDBOpenSUSE struct {
	Source string `json:"source,omitempty"`
}

func (a AffectedDBOpenSUSE) IsZero() bool { return a == AffectedDBOpenSUSE{} }

func NewRecordOpenSUSE(r io.Reader) (*RecordOpenSUSE, error) {
	var rec RecordOpenSUSE
	if err := json.NewDecoder(r).Decode(&rec); err != nil {
		return nil, fmt.Errorf("osv: parse openSUSE: %w", err)
	}
	rec.Ecosystem = osv.EcosystemOpenSUSE
	return &rec, nil
}

// ============================================================
// Ubuntu
// ============================================================

type RecordUbuntu struct {
	osv.Record
	Affected         []AffectedUbuntu `json:"affected,omitempty"`
	DatabaseSpecific TopUbuntu        `json:"database_specific,omitzero"`
}

func (r *RecordUbuntu) Base() *osv.Record  { return &r.Record }
func (r *RecordUbuntu) AffectedAny() []any { return affectedAny(r.Affected) }

type AffectedUbuntu struct {
	osv.AffectedBase
	Ranges            []RangeUbuntu     `json:"ranges,omitempty"`
	EcosystemSpecific AffectedEcoUbuntu `json:"ecosystem_specific,omitzero"`
	DatabaseSpecific  AffectedDBUbuntu  `json:"database_specific,omitzero"`
}

type RangeUbuntu struct{ osv.RangeBase }

type TopUbuntu struct{}

func (TopUbuntu) IsZero() bool { return true }

type AffectedEcoUbuntu struct {
	Availability    string         `json:"availability,omitempty"`
	Binaries        []UbuntuBinary `json:"binaries,omitempty"`
	ModuleNameRegex string         `json:"module_name_regex,omitempty"`
	ModuleVersion   string         `json:"module_version,omitempty"`
	PriorityReason  string         `json:"priority_reason,omitempty"`
	UbuntuPriority  string         `json:"ubuntu_priority,omitempty"`
}

func (a AffectedEcoUbuntu) IsZero() bool {
	return a.Availability == "" && a.Binaries == nil && a.ModuleNameRegex == "" &&
		a.ModuleVersion == "" && a.PriorityReason == "" && a.UbuntuPriority == ""
}

// UbuntuBinary holds either the explicit `{binary_name,
// binary_version}` shape (the standard Ubuntu OSV emitter) or a
// dynamic-key map mirroring SUSE/openSUSE's binaries layout (used by
// some USN records). Both shapes round-trip verbatim.
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

func (a AffectedDBUbuntu) IsZero() bool {
	return a.CVEsMap == nil && a.Source == ""
}

func NewRecordUbuntu(r io.Reader) (*RecordUbuntu, error) {
	var rec RecordUbuntu
	if err := json.NewDecoder(r).Decode(&rec); err != nil {
		return nil, fmt.Errorf("osv: parse Ubuntu: %w", err)
	}
	rec.Ecosystem = osv.EcosystemUbuntu
	return &rec, nil
}

// ============================================================
// VSCode
// ============================================================

type RecordVSCode struct {
	osv.Record
	Affected         []AffectedVSCode `json:"affected,omitempty"`
	DatabaseSpecific TopVSCode        `json:"database_specific,omitzero"`
}

func (r *RecordVSCode) Base() *osv.Record  { return &r.Record }
func (r *RecordVSCode) AffectedAny() []any { return affectedAny(r.Affected) }

type AffectedVSCode struct {
	osv.AffectedBase
	Ranges            []RangeVSCode     `json:"ranges,omitempty"`
	EcosystemSpecific AffectedEcoVSCode `json:"ecosystem_specific,omitzero"`
	DatabaseSpecific  AffectedDBVSCode  `json:"database_specific,omitzero"`
}

type RangeVSCode struct{ osv.RangeBase }

type TopVSCode struct {
	IOCs                     *VSCodeIOCs               `json:"iocs,omitempty"`
	MaliciousPackagesOrigins []VSCodeMalPackagesOrigin `json:"malicious-packages-origins,omitempty"`
}

func (t TopVSCode) IsZero() bool { return t.IOCs == nil && t.MaliciousPackagesOrigins == nil }

type VSCodeIOCs struct {
	Domains []string `json:"domains,omitempty"`
	IPs     []string `json:"ips,omitempty"`
	Strings []string `json:"strings,omitempty"`
	URLs    []string `json:"urls,omitempty"`
}

type VSCodeMalPackagesOrigin struct {
	ID           string                   `json:"id,omitempty"`
	ImportTime   time.Time                `json:"import_time,omitzero"`
	ModifiedTime time.Time                `json:"modified_time,omitzero"`
	Ranges       []VSCodeMalPackagesRange `json:"ranges,omitempty"`
	SHA256       string                   `json:"sha256,omitempty"`
	Source       string                   `json:"source,omitempty"`
	Versions     []string                 `json:"versions,omitempty"`
}

type VSCodeMalPackagesRange struct {
	Events []osv.Event `json:"events,omitempty"`
	Repo   string      `json:"repo,omitempty"`
	Type   string      `json:"type,omitempty"`
}

type AffectedEcoVSCode struct{}

func (AffectedEcoVSCode) IsZero() bool { return true }

type AffectedDBVSCode struct {
	Source string `json:"source,omitempty"`
}

func (a AffectedDBVSCode) IsZero() bool { return a == AffectedDBVSCode{} }

func NewRecordVSCode(r io.Reader) (*RecordVSCode, error) {
	var rec RecordVSCode
	if err := json.NewDecoder(r).Decode(&rec); err != nil {
		return nil, fmt.Errorf("osv: parse VSCode: %w", err)
	}
	rec.Ecosystem = osv.EcosystemVSCode
	return &rec, nil
}

// ============================================================
// opam
// ============================================================

type RecordOpam struct {
	osv.Record
	Affected         []AffectedOpam `json:"affected,omitempty"`
	DatabaseSpecific TopOpam        `json:"database_specific,omitzero"`
}

func (r *RecordOpam) Base() *osv.Record  { return &r.Record }
func (r *RecordOpam) AffectedAny() []any { return affectedAny(r.Affected) }

type AffectedOpam struct {
	osv.AffectedBase
	Ranges            []RangeOpam     `json:"ranges,omitempty"`
	EcosystemSpecific AffectedEcoOpam `json:"ecosystem_specific,omitzero"`
	DatabaseSpecific  AffectedDBOpam  `json:"database_specific,omitzero"`
}

type RangeOpam struct{ osv.RangeBase }

type TopOpam struct {
	CWE       []string `json:"cwe,omitempty"`
	HumanLink string   `json:"human_link,omitempty"`
	OSV       string   `json:"osv,omitempty"`
}

func (t TopOpam) IsZero() bool { return t.CWE == nil && t.HumanLink == "" && t.OSV == "" }

type AffectedEcoOpam struct {
	OpamConstraint string `json:"opam_constraint,omitempty"`
}

func (a AffectedEcoOpam) IsZero() bool { return a == AffectedEcoOpam{} }

type AffectedDBOpam struct {
	Source string `json:"source,omitempty"`
}

func (a AffectedDBOpam) IsZero() bool { return a == AffectedDBOpam{} }

func NewRecordOpam(r io.Reader) (*RecordOpam, error) {
	var rec RecordOpam
	if err := json.NewDecoder(r).Decode(&rec); err != nil {
		return nil, fmt.Errorf("osv: parse opam: %w", err)
	}
	rec.Ecosystem = osv.EcosystemOpam
	return &rec, nil
}

// ============================================================
// openEuler
// ============================================================

type RecordOpenEuler struct {
	osv.Record
	Affected         []AffectedOpenEuler `json:"affected,omitempty"`
	DatabaseSpecific TopOpenEuler        `json:"database_specific,omitzero"`
}

func (r *RecordOpenEuler) Base() *osv.Record  { return &r.Record }
func (r *RecordOpenEuler) AffectedAny() []any { return affectedAny(r.Affected) }

type AffectedOpenEuler struct {
	osv.AffectedBase
	Ranges            []RangeOpenEuler     `json:"ranges,omitempty"`
	EcosystemSpecific AffectedEcoOpenEuler `json:"ecosystem_specific,omitzero"`
	DatabaseSpecific  AffectedDBOpenEuler  `json:"database_specific,omitzero"`
}

type RangeOpenEuler struct{ osv.RangeBase }

type TopOpenEuler struct {
	Severity string `json:"severity,omitempty"`
}

func (t TopOpenEuler) IsZero() bool { return t == TopOpenEuler{} }

type AffectedEcoOpenEuler struct {
	AArch64 []string `json:"aarch64,omitempty"`
	Noarch  []string `json:"noarch,omitempty"`
	Src     []string `json:"src,omitempty"`
	X8664   []string `json:"x86_64,omitempty"`
}

func (a AffectedEcoOpenEuler) IsZero() bool {
	return a.AArch64 == nil && a.Noarch == nil && a.Src == nil && a.X8664 == nil
}

type AffectedDBOpenEuler struct {
	Source string `json:"source,omitempty"`
}

func (a AffectedDBOpenEuler) IsZero() bool { return a == AffectedDBOpenEuler{} }

func NewRecordOpenEuler(r io.Reader) (*RecordOpenEuler, error) {
	var rec RecordOpenEuler
	if err := json.NewDecoder(r).Decode(&rec); err != nil {
		return nil, fmt.Errorf("osv: parse openEuler: %w", err)
	}
	rec.Ecosystem = osv.EcosystemOpenEuler
	return &rec, nil
}
