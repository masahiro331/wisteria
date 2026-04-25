package unifier

import (
	"strconv"

	"github.com/masahiro331/wisteria/internal/unified"
	"github.com/masahiro331/wisteria/internal/unified/cve"
	"github.com/masahiro331/wisteria/internal/unified/osv"
)

// SourceTag is the "<kind>.<source>" string used by mergeSeverities to
// look up priorityRank. Exposed so the debug command can build it from
// IndexEntry without re-implementing the format.
func SourceTag(kind unified.SourceKind, source string) string {
	if kind == unified.SourceCVE {
		return "cve.mitre"
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
			source: "cve.mitre",
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
