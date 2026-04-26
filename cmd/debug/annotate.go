package debug

import (
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/masahiro331/wisteria/internal/unified/annotator"
	"github.com/masahiro331/wisteria/internal/unified/writer"
	"github.com/masahiro331/wisteria/internal/x/cachedir"
)

// newAnnotateCmd returns `wisteria debug annotate`. It runs Stage 4
// (AnnotateKEV → AnnotateEPSS → AnnotateExploitDB) against an
// existing unified/ tree without rebuilding it from sources — useful
// for iterating on the annotator code or refreshing signal fields
// after `wisteria fetch kev` / `fetch epss` / `fetch exploitdb`
// without paying the Stage 1-3 cost.
//
// Pre-existing UnifiedAdvisory.KEV / EPSS / Exploits values are
// overwritten; records whose CVE-ID is not in the catalog keep
// whatever they already had (this command does not clear stale
// annotations).
func newAnnotateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "annotate",
		Short: "Run Stage 4 (KEV + EPSS + ExploitDB) against an existing unified/ tree",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cacheDirOverride, _ := cmd.Flags().GetString("cache-dir")
			root, err := cachedir.Root(cacheDirOverride)
			if err != nil {
				return err
			}
			sourcesRoot := filepath.Join(root, cachedir.SourcesSubdir)
			outDir, err := writer.OutDir(root)
			if err != nil {
				return err
			}
			return annotator.RunAll(cmd.Context(), sourcesRoot, outDir, cmd.OutOrStdout(), "")
		},
	}
}
