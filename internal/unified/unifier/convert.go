package unifier

import (
	"strconv"
	"strings"

	"github.com/masahiro331/wisteria/internal/unified/osv"
	"github.com/masahiro331/wisteria/pkg/advisory"
	"github.com/masahiro331/wisteria/pkg/advisory/cve"
)

// SourceTag is the "<kind>.<source>" string used by mergeSeverities to
// look up PriorityRank. Exposed so the debug command can build it from
// IndexEntry without re-implementing the format.
func SourceTag(kind advisory.SourceKind, source string) string {
	if kind == advisory.SourceCVE {
		return SourceCVEMitre
	}
	return string(kind) + "." + source
}

// OSVReferences converts upstream OSV references to the unified shape.
// OSV `type` becomes a single tag so mergeReferences can union it with
// CVE `tags`.
func OSVReferences(in []osv.Reference) []advisory.Reference {
	out := make([]advisory.Reference, 0, len(in))
	for _, r := range in {
		var tags []string
		if r.Type != "" {
			tags = []string{r.Type}
		}
		out = append(out, advisory.Reference{URL: r.URL, Tags: tags})
	}
	return out
}

// CVEReferences converts upstream CVE5 references to the unified shape.
func CVEReferences(in []cve.Reference) []advisory.Reference {
	out := make([]advisory.Reference, 0, len(in))
	for _, r := range in {
		out = append(out, advisory.Reference{URL: r.URL, Tags: append([]string(nil), r.Tags...)})
	}
	return out
}

// OSVSeverities converts OSV severity entries (no Vector field upstream;
// `score` carries the full CVSS vector string per OSV schema).
func OSVSeverities(in []osv.Severity, from advisory.Provenance, source string) []severityItem {
	out := make([]severityItem, 0, len(in))
	for _, s := range in {
		out = append(out, severityItem{
			Severity: advisory.Severity{
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
func CVEMetrics(in []cve.Metric, from advisory.Provenance) []severityItem {
	out := make([]severityItem, 0, len(in))
	push := func(typ string, c *cve.CVSS) {
		if c == nil {
			return
		}
		out = append(out, severityItem{
			Severity: advisory.Severity{
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
// strings are skipped so we don't emit blank entries. The Role marker
// is what keeps the two entries distinguishable after the merge.
func OSVDescriptions(rec osv.Record, from advisory.Provenance, source string) []descriptionItem {
	var out []descriptionItem
	if rec.Summary != "" {
		out = append(out, descriptionItem{
			Description: advisory.Description{Role: advisory.DescriptionSummary, Lang: "en", Text: rec.Summary, From: from},
			source:      source,
		})
	}
	if rec.Details != "" {
		out = append(out, descriptionItem{
			Description: advisory.Description{Role: advisory.DescriptionDetails, Lang: "en", Text: rec.Details, From: from},
			source:      source,
		})
	}
	return out
}

// normalizeLang reduces a BCP47 tag to its lowercase primary subtag
// ("en-US" → "en") so the same language never appears under two
// spellings in one merged record.
func normalizeLang(lang string) string {
	if i := strings.IndexByte(lang, '-'); i >= 0 {
		lang = lang[:i]
	}
	return strings.ToLower(lang)
}

// CVEDescriptions converts a single Container's descriptions[]. The
// caller invokes it once for the CNA and once per ADP so each container
// can carry its own Provenance (typically with an "#adp:<name>" suffix
// on the ID for ADPs). cve.Description.Value maps to advisory.Description.Text.
func CVEDescriptions(in []cve.Description, from advisory.Provenance) []descriptionItem {
	out := make([]descriptionItem, 0, len(in))
	for _, d := range in {
		out = append(out, descriptionItem{
			// CVE5 texts are full descriptions, not one-line headlines,
			// so they carry the same "details" role as OSV details.
			Description: advisory.Description{Role: advisory.DescriptionDetails, Lang: normalizeLang(d.Lang), Text: d.Value, From: from},
			source:      SourceCVEMitre,
		})
	}
	return out
}

// OSVAffectedRecords flattens the per-ecosystem `RecordX.Affected`
// slice into one affectedItem per entry, wrapping each in the
// shared `advisory.AffectedRecord` shape. The OSV affected is stored
// as `any` because each ecosystem has its own concrete
// `AffectedX` struct; downstream consumers recover the concrete type
// via `From.Source` (the OSV ecosystem dir name) when they need
// ecosystem-specific fields.
//
// The per-ecosystem Affected slice is obtained through the
// `OSVRecord.AffectedAny` method, so adding a new ecosystem is a
// compile-time-checked obligation (a record type that forgets the
// method fails to satisfy the interface) rather than a silently
// skipped entry in a reflection table.
func OSVAffectedRecords(rec osv.OSVRecord, from advisory.Provenance, source string) []affectedItem {
	if rec == nil {
		return nil
	}
	affs := rec.AffectedAny()
	out := make([]affectedItem, 0, len(affs))
	for _, a := range affs {
		out = append(out, affectedItem{
			record: advisory.AffectedRecord{From: from, OSV: a},
			source: source,
		})
	}
	return out
}

// OSVWeaknesses converts one OSV record's CWE identifiers (typed
// database_specific: GHSA-family `cwe_ids`, opam `cwe`) into weakness
// items. OSV carries bare IDs only, so Description stays empty.
func OSVWeaknesses(rec osv.OSVRecord, from advisory.Provenance, source string) []weaknessItem {
	if rec == nil {
		return nil
	}
	ids := rec.CWEIDs()
	if len(ids) == 0 {
		return nil
	}
	out := make([]weaknessItem, 0, len(ids))
	for _, id := range ids {
		out = append(out, weaknessItem{
			Weakness: advisory.Weakness{CWEID: id, From: from},
			source:   source,
		})
	}
	return out
}

// CVEWeaknesses converts one CVE5 Container's problemTypes[] into
// weakness items. Only entries with a non-empty cweId participate —
// free-text problem types have no join key for the CWE-ID dedup, and
// the CNA's description text is intentionally dropped (the merge
// attaches the official MITRE name instead, so the unified shape does
// not vary by source). The caller invokes it once for the CNA and once
// per ADP so each container keeps its own Provenance.
func CVEWeaknesses(in []cve.ProblemType, from advisory.Provenance) []weaknessItem {
	var out []weaknessItem
	for _, pt := range in {
		for _, d := range pt.Descriptions {
			if d.CWEID == "" {
				continue
			}
			out = append(out, weaknessItem{
				Weakness: advisory.Weakness{CWEID: d.CWEID, From: from},
				source:   SourceCVEMitre,
			})
		}
	}
	return out
}

// CVEAffectedRecords does the same for one CVE5 Container's affected[].
func CVEAffectedRecords(in []cve.Affected, from advisory.Provenance) []affectedItem {
	out := make([]affectedItem, 0, len(in))
	for i := range in {
		aff := in[i]
		out = append(out, affectedItem{
			record: advisory.AffectedRecord{From: from, CVE: &aff},
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
func ADPProvenance(base advisory.Provenance, adp cve.ADP, idx int) advisory.Provenance {
	short := ""
	if adp.ProviderMetadata != nil {
		short = adp.ProviderMetadata.ShortName
	}
	if short == "" {
		short = "idx" + strconv.Itoa(idx)
	}
	return advisory.Provenance{Kind: base.Kind, Path: base.Path, ID: base.ID + "#adp:" + short}
}
