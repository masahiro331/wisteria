package unifier

import (
	"sort"

	"github.com/masahiro331/wisteria/internal/unified"
)

// affectedItem pairs an AffectedRecord with the source tag used for
// priority ordering. Same wrapper pattern as severityItem /
// descriptionItem.
type affectedItem struct {
	record unified.AffectedRecord
	source string
}

// mergeAffected keeps every AffectedRecord verbatim (no semantic merge
// per §8.5; the OSV / CVE substructure is preserved so Phase 2 / 3 can
// reconcile package-name shapes themselves) and orders by source
// priority → Provenance.ID → input index. The trailing index keeps
// reproducibility for the common case of one source emitting N
// AffectedRecords with identical Provenance.
func mergeAffected(in []affectedItem) []unified.AffectedRecord {
	if len(in) == 0 {
		return nil
	}
	indices := make([]int, len(in))
	for i := range in {
		indices[i] = i
	}
	sort.SliceStable(indices, func(a, b int) bool {
		ia, ib := indices[a], indices[b]
		ra, rb := priorityRank(in[ia].source), priorityRank(in[ib].source)
		if ra != rb {
			return ra < rb
		}
		ida, idb := in[ia].record.From.ID, in[ib].record.From.ID
		if ida != idb {
			return ida < idb
		}
		return ia < ib
	})
	out := make([]unified.AffectedRecord, len(in))
	for i, idx := range indices {
		out[i] = in[idx].record
	}
	return out
}
