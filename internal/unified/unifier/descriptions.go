package unifier

import (
	"sort"

	"github.com/masahiro331/wisteria/internal/unified"
)

// descriptionItem pairs an upstream Description with the source tag used
// for priority ordering. Same shape as severityItem; the wrapper keeps
// mergeDescriptions a pure function over already-tagged inputs.
type descriptionItem struct {
	unified.Description
	source string
}

// mergeDescriptions keeps every description as-is (no semantic merge per
// §8.3) and orders them by source priority then language. Tie-break by
// the original input index keeps OSV's Summary-then-Details pair stable
// and gives reproducible JSON output.
func mergeDescriptions(in []descriptionItem) []unified.Description {
	if len(in) == 0 {
		return nil
	}
	indices := make([]int, len(in))
	for i := range in {
		indices[i] = i
	}
	sort.SliceStable(indices, func(a, b int) bool {
		ia, ib := indices[a], indices[b]
		ra, rb := PriorityRank(in[ia].source), PriorityRank(in[ib].source)
		if ra != rb {
			return ra < rb
		}
		if in[ia].Lang != in[ib].Lang {
			return in[ia].Lang < in[ib].Lang
		}
		return ia < ib
	})
	out := make([]unified.Description, len(in))
	for i, idx := range indices {
		out[i] = in[idx].Description
	}
	return out
}
