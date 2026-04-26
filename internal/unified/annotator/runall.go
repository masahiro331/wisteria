package annotator

import (
	"context"
	"fmt"
	"io"
	"time"
)

// RunAll runs the three Stage 4 annotators in order — KEV, EPSS,
// ExploitDB — against an existing Stage 3 unified/ tree. Per-stage
// elapsed time is written to w so cmd/unify and cmd/debug/annotate
// produce the same timing lines they did before the refactor; passing
// nil for w is fine for tests / scripts that don't want output.
//
// Order is fixed by the design rationale in cmd/unify.go: KEV first
// (~1500 entries) to surface missing-target issues quickly, then EPSS,
// then ExploitDB. The three annotators write disjoint fields so a
// different order would be functionally equivalent — but the timing
// log is easier to read when the cheapest stage runs first.
//
// First error wins: subsequent stages do not run. The error message is
// prefixed with the stage name so callers can tell which annotator
// failed without inspecting the wrapped chain.
func RunAll(ctx context.Context, sourcesRoot, outDir string, w io.Writer) error {
	stages := []struct {
		name string
		fn   func(context.Context, string, string) error
	}{
		{"kev", AnnotateKEV},
		{"epss", AnnotateEPSS},
		{"exploitdb", AnnotateExploitDB},
	}
	for _, s := range stages {
		t := time.Now()
		if err := s.fn(ctx, sourcesRoot, outDir); err != nil {
			return fmt.Errorf("annotate %s: %w", s.name, err)
		}
		if w != nil {
			fmt.Fprintf(w, "annotate %-10s %s\n", s.name+":", time.Since(t).Round(time.Millisecond))
		}
	}
	return nil
}
