// Package unified holds the stage-internal plumbing types of the
// unified-advisory pipeline. The public core types (UnifiedAdvisory,
// Provenance, the merged-leaf types, the KEV / EPSS / Exploit-DB signal
// types) live in pkg/advisory so external consumers can import them;
// this package keeps only what never leaves the pipeline.
package unified

import "github.com/masahiro331/wisteria/pkg/advisory"

// IndexEntry is one row of Stage 1's output. Path is relative to the
// sourcesRoot the walker was given — Stage 2 reopens the file by joining
// sourcesRoot with Path, and the same value flows straight into
// Provenance.Path. Kind + Source route writes in Stage 3.
type IndexEntry struct {
	Path     string
	Kind     advisory.SourceKind
	Source   string
	SourceID string
}
