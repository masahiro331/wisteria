package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"

	"github.com/masahiro331/wisteria/internal/unified/annotator"
	"github.com/masahiro331/wisteria/internal/unified/unifier"
	"github.com/masahiro331/wisteria/internal/unified/walker"
	"github.com/masahiro331/wisteria/internal/unified/writer"
	"github.com/masahiro331/wisteria/internal/x/cachedir"
)

// newUnifyCmd builds `wisteria unify --cache-dir <path>`. It runs Stage 1
// (walker.Index) → Stage 2 (unifier.MergePrimary, fanned out per
// PrimaryID) → Stage 3 (writer.Write per record). Each merge result is
// streamed straight to disk so memory stays bounded by the worker pool
// size, not by the total record count (currently ~900k). --concurrency
// controls both the walker pool and the unify→write fan-out (default
// 4× NumCPU; I/O-bound). Stage 4 (annotator.AnnotateKEV →
// AnnotateEPSS) attaches signal data after Stage 3.
func newUnifyCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "unify",
		Short: "Build the unified advisory tree from downloaded sources",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cacheOverride, _ := cmd.Flags().GetString(cacheDirFlag)
			conc, _ := cmd.Flags().GetInt(concurrencyFlag)
			cpuProfile, _ := cmd.Flags().GetString("cpuprofile")
			if conc <= 0 {
				conc = runtime.NumCPU() * 4
			}
			if cpuProfile != "" {
				f, err := os.Create(cpuProfile)
				if err != nil {
					return fmt.Errorf("create cpuprofile: %w", err)
				}
				defer f.Close()
				if err := pprof.StartCPUProfile(f); err != nil {
					return fmt.Errorf("start cpuprofile: %w", err)
				}
				defer pprof.StopCPUProfile()
			}
			root, err := cachedir.Root(cacheOverride)
			if err != nil {
				return err
			}
			sourcesRoot := filepath.Join(root, cachedir.SourcesSubdir)

			ctx := cmd.Context()
			out := cmd.OutOrStdout()

			// Stage 1: build the index.
			t0 := time.Now()
			index, err := walker.Index(ctx, sourcesRoot, walker.WithConcurrency(conc))
			if err != nil {
				return fmt.Errorf("walker.Index: %w", err)
			}
			fmt.Fprintf(out, "stage 1 (walker.Index):  %s, %d PrimaryIDs\n",
				time.Since(t0).Round(time.Millisecond), len(index))

			// Reset the unified/ tree once, up front. Done outside the
			// fan-out so workers can MkdirAll bucket dirs without
			// racing with a background delete.
			outDir, err := writer.Reset(root)
			if err != nil {
				return err
			}

			// Stages 2+3 fused: merge → write per PrimaryID. Memory
			// resident is bounded by the worker pool (≈ conc records
			// in flight), not by total record count.
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
			fmt.Fprintf(out, "stage 2+3 (merge+write): %s\n",
				time.Since(t1).Round(time.Millisecond))

			// Stage 4: annotate. KEV first, then EPSS — order doesn't
			// matter functionally (the two write disjoint fields), but
			// running KEV (~1500 entries) first surfaces missing-target
			// issues quickly before the larger EPSS sweep.
			t2 := time.Now()
			if err := annotator.AnnotateKEV(ctx, sourcesRoot, outDir); err != nil {
				return fmt.Errorf("annotator.AnnotateKEV: %w", err)
			}
			fmt.Fprintf(out, "stage 4 (annotate kev):  %s\n",
				time.Since(t2).Round(time.Millisecond))

			t3 := time.Now()
			if err := annotator.AnnotateEPSS(ctx, sourcesRoot, outDir); err != nil {
				return fmt.Errorf("annotator.AnnotateEPSS: %w", err)
			}
			fmt.Fprintf(out, "stage 4 (annotate epss): %s\n",
				time.Since(t3).Round(time.Millisecond))

			fmt.Fprintf(out, "total: %s; wrote %d advisories to %s\n",
				time.Since(t0).Round(time.Millisecond), len(index), outDir)
			return nil
		},
	}
	c.Flags().Int(
		concurrencyFlag, 0,
		"per-stage worker pool size (default 4× NumCPU)",
	)
	c.Flags().String(
		"cpuprofile", "",
		"write CPU profile to this file (use with `go tool pprof <file>`)",
	)
	return c
}
