package unifier

import (
	"sort"

	"github.com/masahiro331/wisteria/internal/unified"
)

// severityItem pairs an upstream Severity with the source tag used for
// priority ordering ("cve.mitre", "osv.AlmaLinux", ...). The tag must be
// supplied by the caller so mergeSeverities stays a pure function over
// already-tagged inputs (no Provenance.Path string parsing).
type severityItem struct {
	unified.Severity
	source string
}

// mergeSeverities dedups severity assessments and sorts them by source
// priority then Type (§8.4). Dedup keys:
//
//   - primary: (Type, Vector) when Vector is non-empty
//   - fallback: (Type, Score) when Vector is empty
//
// Within a dedup bucket the entry with the highest-priority source wins;
// its Provenance is the one returned. Vector vs no-Vector entries with
// the same Type are intentionally not collapsed because the keys differ.
func mergeSeverities(in []severityItem) []unified.Severity {
	if len(in) == 0 {
		return nil
	}
	type key struct{ a, b, c string }
	makeKey := func(s unified.Severity) key {
		if s.Vector != "" {
			return key{a: s.Type, b: "v", c: s.Vector}
		}
		return key{a: s.Type, b: "s", c: s.Score}
	}
	type bucket struct {
		item severityItem
		rank int
	}
	buckets := make(map[key]*bucket)
	for _, item := range in {
		k := makeKey(item.Severity)
		r := priorityRank(item.source)
		if b, ok := buckets[k]; !ok || r < b.rank {
			buckets[k] = &bucket{item: item, rank: r}
		}
	}
	out := make([]severityItem, 0, len(buckets))
	for _, b := range buckets {
		out = append(out, b.item)
	}
	sort.SliceStable(out, func(i, j int) bool {
		ri, rj := priorityRank(out[i].source), priorityRank(out[j].source)
		if ri != rj {
			return ri < rj
		}
		return out[i].Type < out[j].Type
	})
	res := make([]unified.Severity, len(out))
	for i, x := range out {
		res[i] = x.Severity
	}
	return res
}
