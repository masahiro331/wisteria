package unifier

import (
	"cmp"

	"github.com/masahiro331/wisteria/pkg/advisory"
)

// affectedItem pairs an AffectedRecord with the source tag used for
// priority ordering. Same wrapper pattern as severityItem /
// descriptionItem.
type affectedItem struct {
	record advisory.AffectedRecord
	source string
}

// mergeAffected keeps every AffectedRecord verbatim (no semantic merge
// per §8.5; the OSV / CVE substructure is preserved so Phase 2 / 3 can
// reconcile package-name shapes themselves) and orders by source
// priority → Provenance.ID → input index. The trailing index keeps
// reproducibility for the common case of one source emitting N
// AffectedRecords with identical Provenance.
func mergeAffected(in []affectedItem) []advisory.AffectedRecord {
	sorted := stableSortByPriority(
		in,
		func(it affectedItem) string { return it.source },
		func(a, b affectedItem) int { return cmp.Compare(a.record.From.ID, b.record.From.ID) },
	)
	if sorted == nil {
		return nil
	}
	out := make([]advisory.AffectedRecord, len(sorted))
	for i, it := range sorted {
		out[i] = it.record
	}
	return out
}
