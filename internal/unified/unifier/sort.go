package unifier

import "sort"

// stableSortByPriority is the parallel-hold sort shared by §8.3
// (descriptions) / §8.5 (affected) and reused for the post-dedup
// ordering of §8.4 (severities). It returns a new slice ordered by:
//
//  1. PriorityRank(source(item)) ascending (cve.mitre < osv.AlmaLinux < ...)
//  2. cmpSecondary(a, b) — caller-provided field comparator returning
//     the usual -1 / 0 / +1 (e.g. Lang for descriptions, Provenance.ID
//     for affected, (Type, Vector, Score) for severities)
//  3. original input index (sort.SliceStable preserves equals)
//
// cmpSecondary follows the cmp.Compare / slices.SortFunc convention so
// callers can build it from cmp.Compare on a single field or chain
// several with the usual "if !=, return cmp.Compare(...)" pattern.
//
// nil input returns nil so callers can stay omitempty-friendly.
func stableSortByPriority[T any](
	in []T,
	source func(T) string,
	cmpSecondary func(a, b T) int,
) []T {
	if len(in) == 0 {
		return nil
	}
	indices := make([]int, len(in))
	for i := range in {
		indices[i] = i
	}
	sort.SliceStable(indices, func(a, b int) bool {
		ia, ib := indices[a], indices[b]
		ra, rb := PriorityRank(source(in[ia])), PriorityRank(source(in[ib]))
		if ra != rb {
			return ra < rb
		}
		if c := cmpSecondary(in[ia], in[ib]); c != 0 {
			return c < 0
		}
		return ia < ib
	})
	out := make([]T, len(in))
	for i, idx := range indices {
		out[i] = in[idx]
	}
	return out
}
