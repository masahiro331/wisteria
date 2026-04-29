package annotator

import (
	"context"
	"fmt"
	"io"
	"time"
)

// RunAll runs the four Stage 4 annotators in order — KEV, EPSS,
// ExploitDB, Nuclei — against an existing Stage 3 unified/ tree.
// Per-stage elapsed time is written to w; passing nil for w is fine
// for tests / scripts that don't want output.
//
// linePrefix is prepended verbatim to every timing line so the same
// helper can serve `wisteria unify` (which wants its lines under a
// "stage 4 " banner to align with stage 1 / 2+3 lines) and
// `wisteria debug annotate` (which runs Stage 4 in isolation and
// wants no extra prefix). Pass "" for the no-prefix shape.
//
// Order is fixed: KEV first (~1500 entries) to surface missing-target
// issues quickly, then EPSS, then ExploitDB, then Nuclei. All four
// annotators write disjoint fields so a different order would be
// functionally equivalent — but the timing log is easier to read when
// the cheapest stage runs first.
//
// First error wins: subsequent stages do not run. The error message is
// prefixed with the stage name so callers can tell which annotator
// failed without inspecting the wrapped chain.
func RunAll(ctx context.Context, sourcesRoot, outDir string, w io.Writer, linePrefix string) error {
	stages := []struct {
		name string
		fn   func(context.Context, string, string) error
	}{
		{"kev", AnnotateKEV},
		{"epss", AnnotateEPSS},
		{"exploitdb", AnnotateExploitDB},
		{"nuclei", AnnotateNuclei},
	}
	for _, s := range stages {
		t := time.Now()
		if err := s.fn(ctx, sourcesRoot, outDir); err != nil {
			return fmt.Errorf("annotate %s: %w", s.name, err)
		}
		if w != nil {
			fmt.Fprintf(w, "%sannotate %-10s %s\n",
				linePrefix, s.name+":",
				time.Since(t).Round(time.Millisecond))
		}
	}
	return nil
}
