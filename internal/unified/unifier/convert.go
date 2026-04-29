package unifier

import (
	"reflect"
	"strconv"

	"github.com/masahiro331/wisteria/internal/unified"
	"github.com/masahiro331/wisteria/internal/unified/cve"
	"github.com/masahiro331/wisteria/internal/unified/osv"
)

// SourceTag is the "<kind>.<source>" string used by mergeSeverities to
// look up PriorityRank. Exposed so the debug command can build it from
// IndexEntry without re-implementing the format.
func SourceTag(kind unified.SourceKind, source string) string {
	if kind == unified.SourceCVE {
		return SourceCVEMitre
	}
	return string(kind) + "." + source
}

// OSVReferences converts upstream OSV references to the unified shape.
// OSV `type` becomes a single tag so mergeReferences can union it with
// CVE `tags`.
func OSVReferences(in []osv.Reference) []unified.Reference {
	out := make([]unified.Reference, 0, len(in))
	for _, r := range in {
		var tags []string
		if r.Type != "" {
			tags = []string{r.Type}
		}
		out = append(out, unified.Reference{URL: r.URL, Tags: tags})
	}
	return out
}

// CVEReferences converts upstream CVE5 references to the unified shape.
func CVEReferences(in []cve.Reference) []unified.Reference {
	out := make([]unified.Reference, 0, len(in))
	for _, r := range in {
		out = append(out, unified.Reference{URL: r.URL, Tags: append([]string(nil), r.Tags...)})
	}
	return out
}

// OSVSeverities converts OSV severity entries (no Vector field upstream;
// `score` carries the full CVSS vector string per OSV schema).
func OSVSeverities(in []osv.Severity, from unified.Provenance, source string) []severityItem {
	out := make([]severityItem, 0, len(in))
	for _, s := range in {
		out = append(out, severityItem{
			Severity: unified.Severity{
				Type:   s.Type,
				Vector: s.Score, // OSV `score` is the vector string
				From:   from,
			},
			source: source,
		})
	}
	return out
}

// CVEMetrics flattens CVE5 Metrics (CVSS v2.0 / v2 / v3.0 / v3.1 / v4.0)
// into severity items. Non-CVSS Metric.Other is skipped — it carries
// SSVC / KEV-like signals that don't fit the (Type, Vector, Score) shape
// and aren't part of the §8.4 dedup contract.
func CVEMetrics(in []cve.Metric, from unified.Provenance) []severityItem {
	out := make([]severityItem, 0, len(in))
	push := func(typ string, c *cve.CVSS) {
		if c == nil {
			return
		}
		out = append(out, severityItem{
			Severity: unified.Severity{
				Type:   typ,
				Vector: c.VectorString,
				Score:  formatScore(c.BaseScore),
				From:   from,
			},
			source: SourceCVEMitre,
		})
	}
	for _, m := range in {
		push("CVSS_V2", m.CVSSv20)
		push("CVSS_V2", m.CVSSv2)
		push("CVSS_V3", m.CVSSv30)
		push("CVSS_V3", m.CVSSv31)
		push("CVSS_V4", m.CVSSv40)
	}
	return out
}

func formatScore(p *float64) string {
	if p == nil {
		return ""
	}
	return strconv.FormatFloat(*p, 'f', -1, 64)
}

// OSVDescriptions emits up to two parallel descriptions per record:
// Summary then Details, both as English text. Lang is fixed to "en"
// because OSV schema does not carry a per-text lang field. Empty
// strings are skipped so we don't emit blank entries.
func OSVDescriptions(rec osv.Record, from unified.Provenance, source string) []descriptionItem {
	var out []descriptionItem
	if rec.Summary != "" {
		out = append(out, descriptionItem{
			Description: unified.Description{Lang: "en", Text: rec.Summary, From: from},
			source:      source,
		})
	}
	if rec.Details != "" {
		out = append(out, descriptionItem{
			Description: unified.Description{Lang: "en", Text: rec.Details, From: from},
			source:      source,
		})
	}
	return out
}

// CVEDescriptions converts a single Container's descriptions[]. The
// caller invokes it once for the CNA and once per ADP so each container
// can carry its own Provenance (typically with an "#adp:<name>" suffix
// on the ID for ADPs). cve.Description.Value maps to unified.Description.Text.
func CVEDescriptions(in []cve.Description, from unified.Provenance) []descriptionItem {
	out := make([]descriptionItem, 0, len(in))
	for _, d := range in {
		out = append(out, descriptionItem{
			Description: unified.Description{Lang: d.Lang, Text: d.Value, From: from},
			source:      SourceCVEMitre,
		})
	}
	return out
}

// OSVAffectedRecords flattens the per-ecosystem `RecordX.Affected`
// slice into one affectedItem per entry, wrapping each in the
// shared `unified.AffectedRecord` shape. The OSV affected is stored
// as `any` because each ecosystem has its own concrete
// `AffectedX` struct; downstream consumers recover the concrete type
// via `From.Source` (the OSV ecosystem dir name) when they need
// ecosystem-specific fields.
func OSVAffectedRecords(rec osv.OSVRecord, from unified.Provenance, source string) []affectedItem {
	affs := osvAffectedSlice(rec)
	out := make([]affectedItem, 0, len(affs))
	for _, a := range affs {
		out = append(out, affectedItem{
			record: unified.AffectedRecord{From: from, OSV: a},
			source: source,
		})
	}
	return out
}

// osvAffectedSlice returns each ecosystem's `Affected` slice as
// []any, preserving the concrete element type (`*AffectedPyPI`,
// `*AffectedUbuntu`, ...). The lookup goes through a per-type
// extractor map so the cyclomatic complexity stays manageable as the
// ecosystem list grows. Adding a new ecosystem extends the map.
func osvAffectedSlice(rec osv.OSVRecord) []any {
	if rec == nil {
		return nil
	}
	if extract, ok := osvAffectedExtractors[reflect.TypeOf(rec)]; ok {
		return extract(rec)
	}
	return nil
}

// osvAffectedExtractors maps each concrete `*RecordX` type to a
// closure that returns its Affected slice as []any. Indexed by
// reflect.Type because Go does not allow "type values" as map keys.
var osvAffectedExtractors = map[reflect.Type]func(osv.OSVRecord) []any{
	reflect.TypeOf((*osv.RecordAlmaLinux)(nil)):                  func(r osv.OSVRecord) []any { return wrapAffected(r.(*osv.RecordAlmaLinux).Affected) },
	reflect.TypeOf((*osv.RecordAlpaquita)(nil)):                  func(r osv.OSVRecord) []any { return wrapAffected(r.(*osv.RecordAlpaquita).Affected) },
	reflect.TypeOf((*osv.RecordAlpine)(nil)):                     func(r osv.OSVRecord) []any { return wrapAffected(r.(*osv.RecordAlpine).Affected) },
	reflect.TypeOf((*osv.RecordAndroid)(nil)):                    func(r osv.OSVRecord) []any { return wrapAffected(r.(*osv.RecordAndroid).Affected) },
	reflect.TypeOf((*osv.RecordAzureLinux)(nil)):                 func(r osv.OSVRecord) []any { return wrapAffected(r.(*osv.RecordAzureLinux).Affected) },
	reflect.TypeOf((*osv.RecordBellSoftHardenedContainers)(nil)): func(r osv.OSVRecord) []any { return wrapAffected(r.(*osv.RecordBellSoftHardenedContainers).Affected) },
	reflect.TypeOf((*osv.RecordBitnami)(nil)):                    func(r osv.OSVRecord) []any { return wrapAffected(r.(*osv.RecordBitnami).Affected) },
	reflect.TypeOf((*osv.RecordCRAN)(nil)):                       func(r osv.OSVRecord) []any { return wrapAffected(r.(*osv.RecordCRAN).Affected) },
	reflect.TypeOf((*osv.RecordChainguard)(nil)):                 func(r osv.OSVRecord) []any { return wrapAffected(r.(*osv.RecordChainguard).Affected) },
	reflect.TypeOf((*osv.RecordCleanStart)(nil)):                 func(r osv.OSVRecord) []any { return wrapAffected(r.(*osv.RecordCleanStart).Affected) },
	reflect.TypeOf((*osv.RecordCratesIO)(nil)):                   func(r osv.OSVRecord) []any { return wrapAffected(r.(*osv.RecordCratesIO).Affected) },
	reflect.TypeOf((*osv.RecordDebian)(nil)):                     func(r osv.OSVRecord) []any { return wrapAffected(r.(*osv.RecordDebian).Affected) },
	reflect.TypeOf((*osv.RecordEcho)(nil)):                       func(r osv.OSVRecord) []any { return wrapAffected(r.(*osv.RecordEcho).Affected) },
	reflect.TypeOf((*osv.RecordGHC)(nil)):                        func(r osv.OSVRecord) []any { return wrapAffected(r.(*osv.RecordGHC).Affected) },
	reflect.TypeOf((*osv.RecordGIT)(nil)):                        func(r osv.OSVRecord) []any { return wrapAffected(r.(*osv.RecordGIT).Affected) },
	reflect.TypeOf((*osv.RecordGSD)(nil)):                        func(r osv.OSVRecord) []any { return wrapAffected(r.(*osv.RecordGSD).Affected) },
	reflect.TypeOf((*osv.RecordGeneric)(nil)):                    func(r osv.OSVRecord) []any { return wrapAffected(r.(*osv.RecordGeneric).Affected) },
	reflect.TypeOf((*osv.RecordGitHubActions)(nil)):              func(r osv.OSVRecord) []any { return wrapAffected(r.(*osv.RecordGitHubActions).Affected) },
	reflect.TypeOf((*osv.RecordGo)(nil)):                         func(r osv.OSVRecord) []any { return wrapAffected(r.(*osv.RecordGo).Affected) },
	reflect.TypeOf((*osv.RecordHackage)(nil)):                    func(r osv.OSVRecord) []any { return wrapAffected(r.(*osv.RecordHackage).Affected) },
	reflect.TypeOf((*osv.RecordHex)(nil)):                        func(r osv.OSVRecord) []any { return wrapAffected(r.(*osv.RecordHex).Affected) },
	reflect.TypeOf((*osv.RecordJulia)(nil)):                      func(r osv.OSVRecord) []any { return wrapAffected(r.(*osv.RecordJulia).Affected) },
	reflect.TypeOf((*osv.RecordLinux)(nil)):                      func(r osv.OSVRecord) []any { return wrapAffected(r.(*osv.RecordLinux).Affected) },
	reflect.TypeOf((*osv.RecordMageia)(nil)):                     func(r osv.OSVRecord) []any { return wrapAffected(r.(*osv.RecordMageia).Affected) },
	reflect.TypeOf((*osv.RecordMaven)(nil)):                      func(r osv.OSVRecord) []any { return wrapAffected(r.(*osv.RecordMaven).Affected) },
	reflect.TypeOf((*osv.RecordMinimOS)(nil)):                    func(r osv.OSVRecord) []any { return wrapAffected(r.(*osv.RecordMinimOS).Affected) },
	reflect.TypeOf((*osv.RecordNuGet)(nil)):                      func(r osv.OSVRecord) []any { return wrapAffected(r.(*osv.RecordNuGet).Affected) },
	reflect.TypeOf((*osv.RecordOSSFuzz)(nil)):                    func(r osv.OSVRecord) []any { return wrapAffected(r.(*osv.RecordOSSFuzz).Affected) },
	reflect.TypeOf((*osv.RecordPackagist)(nil)):                  func(r osv.OSVRecord) []any { return wrapAffected(r.(*osv.RecordPackagist).Affected) },
	reflect.TypeOf((*osv.RecordPub)(nil)):                        func(r osv.OSVRecord) []any { return wrapAffected(r.(*osv.RecordPub).Affected) },
	reflect.TypeOf((*osv.RecordPyPI)(nil)):                       func(r osv.OSVRecord) []any { return wrapAffected(r.(*osv.RecordPyPI).Affected) },
	reflect.TypeOf((*osv.RecordRedHat)(nil)):                     func(r osv.OSVRecord) []any { return wrapAffected(r.(*osv.RecordRedHat).Affected) },
	reflect.TypeOf((*osv.RecordRockyLinux)(nil)):                 func(r osv.OSVRecord) []any { return wrapAffected(r.(*osv.RecordRockyLinux).Affected) },
	reflect.TypeOf((*osv.RecordRoot)(nil)):                       func(r osv.OSVRecord) []any { return wrapAffected(r.(*osv.RecordRoot).Affected) },
	reflect.TypeOf((*osv.RecordRubyGems)(nil)):                   func(r osv.OSVRecord) []any { return wrapAffected(r.(*osv.RecordRubyGems).Affected) },
	reflect.TypeOf((*osv.RecordSUSE)(nil)):                       func(r osv.OSVRecord) []any { return wrapAffected(r.(*osv.RecordSUSE).Affected) },
	reflect.TypeOf((*osv.RecordSwiftURL)(nil)):                   func(r osv.OSVRecord) []any { return wrapAffected(r.(*osv.RecordSwiftURL).Affected) },
	reflect.TypeOf((*osv.RecordUVI)(nil)):                        func(r osv.OSVRecord) []any { return wrapAffected(r.(*osv.RecordUVI).Affected) },
	reflect.TypeOf((*osv.RecordUbuntu)(nil)):                     func(r osv.OSVRecord) []any { return wrapAffected(r.(*osv.RecordUbuntu).Affected) },
	reflect.TypeOf((*osv.RecordVSCode)(nil)):                     func(r osv.OSVRecord) []any { return wrapAffected(r.(*osv.RecordVSCode).Affected) },
	reflect.TypeOf((*osv.RecordWolfi)(nil)):                      func(r osv.OSVRecord) []any { return wrapAffected(r.(*osv.RecordWolfi).Affected) },
	reflect.TypeOf((*osv.RecordNpm)(nil)):                        func(r osv.OSVRecord) []any { return wrapAffected(r.(*osv.RecordNpm).Affected) },
	reflect.TypeOf((*osv.RecordOpam)(nil)):                       func(r osv.OSVRecord) []any { return wrapAffected(r.(*osv.RecordOpam).Affected) },
	reflect.TypeOf((*osv.RecordOpenEuler)(nil)):                  func(r osv.OSVRecord) []any { return wrapAffected(r.(*osv.RecordOpenEuler).Affected) },
	reflect.TypeOf((*osv.RecordOpenSUSE)(nil)):                   func(r osv.OSVRecord) []any { return wrapAffected(r.(*osv.RecordOpenSUSE).Affected) },
}

// wrapAffected captures each element by value and returns a slice of
// pointers (typed at compile time, erased to `any` for the wrapper).
// This preserves the source-side substructure without losing the
// concrete type for json.Marshal.
func wrapAffected[T any](in []T) []any {
	out := make([]any, len(in))
	for i := range in {
		v := in[i]
		out[i] = &v
	}
	return out
}

// CVEAffectedRecords does the same for one CVE5 Container's affected[].
func CVEAffectedRecords(in []cve.Affected, from unified.Provenance) []affectedItem {
	out := make([]affectedItem, 0, len(in))
	for i := range in {
		aff := in[i]
		out = append(out, affectedItem{
			record: unified.AffectedRecord{From: from, CVE: &aff},
			source: SourceCVEMitre,
		})
	}
	return out
}

// ADPProvenance derives a Provenance for one ADP container of a CVE5
// record. CVE5 spec allows multiple ADPs per record (CISA Vulnrichment,
// Red Hat etc.); we suffix the ID with "#adp:<shortName>" so the
// downstream merge functions can sort CNA before its ADPs and tell them
// apart in JSON. providerShortName falls back to the slice index when
// the ADP omits its providerMetadata.
func ADPProvenance(base unified.Provenance, adp cve.ADP, idx int) unified.Provenance {
	short := ""
	if adp.ProviderMetadata != nil {
		short = adp.ProviderMetadata.ShortName
	}
	if short == "" {
		short = "idx" + strconv.Itoa(idx)
	}
	return unified.Provenance{Kind: base.Kind, Path: base.Path, ID: base.ID + "#adp:" + short}
}
