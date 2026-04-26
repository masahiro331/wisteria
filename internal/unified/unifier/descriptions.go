package unifier

import (
	"cmp"

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
	sorted := stableSortByPriority(
		in,
		func(it descriptionItem) string { return it.source },
		func(a, b descriptionItem) int { return cmp.Compare(a.Lang, b.Lang) },
	)
	if sorted == nil {
		return nil
	}
	out := make([]unified.Description, len(sorted))
	for i, it := range sorted {
		out[i] = it.Description
	}
	return out
}
