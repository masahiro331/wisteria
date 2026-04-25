package debug

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/masahiro331/wisteria/internal/unified/annotator"
	"github.com/masahiro331/wisteria/internal/x/cachedir"
)

// newAnnotateCmd returns `wisteria debug annotate`. It runs Stage 4
// (AnnotateKEV → AnnotateEPSS) against an existing unified/ tree
// without rebuilding it from sources — useful for iterating on the
// annotator code or refreshing signal fields after `wisteria fetch
// kev` / `fetch epss` without paying the Stage 1-3 cost.
//
// Pre-existing UnifiedAdvisory.KEV / EPSS values are overwritten;
// records whose CVE-ID is not in the catalog keep whatever they
// already had (this command does not clear stale annotations).
func newAnnotateCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "annotate",
		Short: "Run Stage 4 (KEV + EPSS) against an existing unified/ tree",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cacheDirOverride, _ := cmd.Flags().GetString("cache-dir")
			root, err := cachedir.Root(cacheDirOverride)
			if err != nil {
				return err
			}
			sourcesRoot := filepath.Join(root, cachedir.SourcesSubdir)
			outDir := filepath.Join(root, "unified")
			out := cmd.OutOrStdout()
			ctx := cmd.Context()

			t0 := time.Now()
			if err := annotator.AnnotateKEV(ctx, sourcesRoot, outDir); err != nil {
				return fmt.Errorf("annotator.AnnotateKEV: %w", err)
			}
			fmt.Fprintf(out, "annotate kev:  %s\n", time.Since(t0).Round(time.Millisecond))

			t1 := time.Now()
			if err := annotator.AnnotateEPSS(ctx, sourcesRoot, outDir); err != nil {
				return fmt.Errorf("annotator.AnnotateEPSS: %w", err)
			}
			fmt.Fprintf(out, "annotate epss: %s\n", time.Since(t1).Round(time.Millisecond))

			return nil
		},
	}
	return c
}
