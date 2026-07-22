package unifier

import (
	"cmp"

	"github.com/masahiro331/wisteria/pkg/advisory"
)

// weaknessItem pairs an upstream Weakness with the source tag used for
// priority ordering, mirroring severityItem — mergeWeaknesses stays a
// pure function over already-tagged inputs.
type weaknessItem struct {
	advisory.Weakness
	source string
}

// mergeWeaknesses dedups CWE assignments and sorts them by source
// priority then CWE-ID. Dedup key is the CWE-ID alone: unlike
// severities, two sources asserting the same CWE are the same claim,
// so the entry from the highest-priority source wins (it usually also
// carries the CVE5 description text).
func mergeWeaknesses(in []weaknessItem) []advisory.Weakness {
	if len(in) == 0 {
		return nil
	}
	type bucket struct {
		item weaknessItem
		rank int
	}
	buckets := make(map[string]*bucket)
	for _, item := range in {
		r := PriorityRank(item.source)
		if b, ok := buckets[item.CWEID]; !ok || r < b.rank {
			buckets[item.CWEID] = &bucket{item: item, rank: r}
		}
	}
	deduped := make([]weaknessItem, 0, len(buckets))
	for _, b := range buckets {
		deduped = append(deduped, b.item)
	}
	sorted := stableSortByPriority(
		deduped,
		func(it weaknessItem) string { return it.source },
		func(a, b weaknessItem) int { return cmp.Compare(a.CWEID, b.CWEID) },
	)
	out := make([]advisory.Weakness, len(sorted))
	for i, it := range sorted {
		out[i] = it.Weakness
	}
	return out
}
