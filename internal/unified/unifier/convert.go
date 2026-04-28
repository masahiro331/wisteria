package unifier

import (
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

// OSVAffectedRecords wraps each osv.Affected as an AffectedRecord with
// the source-side substructure preserved (no field-by-field copy).
func OSVAffectedRecords(in []osv.Affected, from unified.Provenance, source string) []affectedItem {
	out := make([]affectedItem, 0, len(in))
	for i := range in {
		aff := in[i] // copy so the &aff escape doesn't share the loop var
		out = append(out, affectedItem{
			record: unified.AffectedRecord{From: from, OSV: &aff},
			source: source,
		})
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
