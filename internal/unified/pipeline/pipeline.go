// Package pipeline orchestrates the full unified-advisory build:
// Stage 1 (walker.Index) → Stage 2 (unifier.MergePrimary, fanned out per
// PrimaryID) → Stage 3 (writer.Write per record, streaming) → Stage 4
// (annotator.RunAll). It exists so cmd/unify can stay a thin Cobra
// shell that only owns flag parsing and pprof; everything else
// (concurrency, fan-out, error policy, per-stage timing) lives here
// where it can be tested without spinning up a Cobra command.
//
// Memory resident is bounded by the worker pool (≈ Concurrency records
// in flight), not by total record count — the merge-then-write
// fan-out streams each record to disk before reading the next one.
package pipeline

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"runtime"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/masahiro331/wisteria/internal/unified/annotator"
	"github.com/masahiro331/wisteria/internal/unified/unifier"
	"github.com/masahiro331/wisteria/internal/unified/walker"
	"github.com/masahiro331/wisteria/internal/unified/writer"
	"github.com/masahiro331/wisteria/internal/x/cachedir"
)

// Options bundles per-invocation knobs. Concurrency = 0 means "use the
// default" (4× NumCPU; the work is I/O-bound so we oversubscribe). The
// zero value is a valid Options.
type Options struct {
	// Concurrency caps both the walker pool and the Stage 2+3 fan-out.
	// Same knob is shared so a single --concurrency flag controls the
	// whole pipeline; bumping the walker without bumping fan-out (or
	// vice versa) tends to just shift the bottleneck.
	Concurrency int
}

// Run executes Stages 1-4 against cacheDir. cacheDir is the override
// passed to cachedir.Root — empty means "resolve the default" ($HOME
// based, env-var aware). w receives per-stage timing lines; pass nil
// to suppress.
//
// Errors abort the pipeline at the first failure. Stage 1 errors are
// returned as-is from walker.Index; Stage 2+3 errors carry the
// PrimaryID; Stage 4 errors carry the annotator name (kev / epss /
// exploitdb).
func Run(ctx context.Context, cacheDir string, opts Options, w io.Writer) error {
	conc := opts.Concurrency
	if conc <= 0 {
		conc = runtime.NumCPU() * 4
	}
	root, err := cachedir.Root(cacheDir)
	if err != nil {
		return err
	}
	sourcesRoot := filepath.Join(root, cachedir.SourcesSubdir)

	// Stage 1: build the index.
	t0 := time.Now()
	index, err := walker.Index(ctx, sourcesRoot, walker.WithConcurrency(conc))
	if err != nil {
		return fmt.Errorf("walker.Index: %w", err)
	}
	logf(w, "stage 1 (walker.Index):  %s, %d PrimaryIDs\n",
		time.Since(t0).Round(time.Millisecond), len(index))

	// Reset the unified/ tree once, up front. Done outside the fan-out
	// so workers can MkdirAll bucket dirs without racing with a
	// background delete.
	outDir, err := writer.Reset(root)
	if err != nil {
		return err
	}

	// Stages 2+3 fused: merge → write per PrimaryID. Memory resident is
	// bounded by the worker pool (≈ conc records in flight), not by
	// total record count.
	t1 := time.Now()
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(conc)
	for id, entries := range index {
		g.Go(func() error {
			rec, err := unifier.MergePrimary(gctx, sourcesRoot, id, entries)
			if err != nil {
				return fmt.Errorf("merge %s: %w", id, err)
			}
			return writer.Write(outDir, rec)
		})
	}
	if err := g.Wait(); err != nil {
		return err
	}
	logf(w, "stage 2+3 (merge+write): %s\n",
		time.Since(t1).Round(time.Millisecond))

	// Stage 4: annotate.
	if err := annotator.RunAll(ctx, sourcesRoot, outDir, w); err != nil {
		return err
	}

	logf(w, "total: %s; wrote %d advisories to %s\n",
		time.Since(t0).Round(time.Millisecond), len(index), outDir)
	return nil
}

func logf(w io.Writer, format string, a ...any) {
	if w == nil {
		return
	}
	fmt.Fprintf(w, format, a...)
}
