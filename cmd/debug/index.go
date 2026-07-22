package debug

import (
	"fmt"
	"path/filepath"
	"sort"

	"github.com/spf13/cobra"

	"github.com/masahiro331/wisteria/internal/unified"
	"github.com/masahiro331/wisteria/internal/unified/walker"
	"github.com/masahiro331/wisteria/internal/x/cachedir"
	"github.com/masahiro331/wisteria/pkg/advisory"
)

// newIndexCmd returns `wisteria debug index`. With no flag it prints a
// distribution summary of the walker output; with --id it lists the
// IndexEntry paths registered under that PrimaryID. Resolves the cache
// dir via the same precedence as `wisteria fetch`.
func newIndexCmd() *cobra.Command {
	var id string
	c := &cobra.Command{
		Use:   "index",
		Short: "Run walker.Index and print map size / distribution (or --id to list entries)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cacheDirOverride, _ := cmd.Flags().GetString("cache-dir")
			root, err := cachedir.Root(cacheDirOverride)
			if err != nil {
				return err
			}
			sourcesRoot := filepath.Join(root, cachedir.SourcesSubdir)

			idx, err := walker.Index(cmd.Context(), sourcesRoot, walker.WithWarnLog(cmd.ErrOrStderr()))
			if err != nil {
				return fmt.Errorf("walker.Index: %w", err)
			}

			if id != "" {
				return printID(cmd, idx, id)
			}
			printDistribution(cmd, idx)
			return nil
		},
	}
	c.Flags().StringVar(&id, "id", "", "PrimaryID (CVE-ID or source-derived id) to list entries for")
	return c
}

// printID writes "PrimaryID\n  <kind> <source> <path>" lines, one per
// IndexEntry under id. Returns an error (non-zero exit) when the id is
// not in the index — this lets CI / shell pipelines branch on existence
// without parsing stdout.
func printID(cmd *cobra.Command, idx map[string][]unified.IndexEntry, id string) error {
	entries, ok := idx[id]
	if !ok {
		return fmt.Errorf("PrimaryID %q not found in index", id)
	}
	out := cmd.OutOrStdout()
	fmt.Fprintln(out, id)
	for _, e := range entries {
		fmt.Fprintf(out, "  %s\t%s\t%s\n", e.Kind, e.Source, e.Path)
	}
	return nil
}

// printDistribution emits four blocks, in order:
//
//   - PrimaryIDs total
//   - per-Kind entry count (osv: N, cve: M)
//   - PrimaryID -> entry-count histogram (1: a, 2: b, ...) so we can
//     spot how often advisories converge across sources
//   - per-OSV-ecosystem entry count, sorted alphabetically
//
// Counts are over IndexEntry occurrences (not unique files) so a single
// OSV file aliased to N CVEs correctly contributes N to the OSV total.
func printDistribution(cmd *cobra.Command, idx map[string][]unified.IndexEntry) {
	out := cmd.OutOrStdout()

	kindCounts := map[advisory.SourceKind]int{}
	histogram := map[int]int{}
	ecoCounts := map[string]int{}
	for _, entries := range idx {
		histogram[len(entries)]++
		for _, e := range entries {
			kindCounts[e.Kind]++
			if e.Kind == advisory.SourceOSV {
				ecoCounts[e.Source]++
			}
		}
	}

	fmt.Fprintf(out, "PrimaryIDs: %d\n", len(idx))

	fmt.Fprintln(out, "By Kind:")
	for _, k := range []advisory.SourceKind{advisory.SourceOSV, advisory.SourceCVE} {
		if v, ok := kindCounts[k]; ok {
			fmt.Fprintf(out, "  %s: %d\n", k, v)
		}
	}

	fmt.Fprintln(out, "Entries per PrimaryID:")
	sizes := make([]int, 0, len(histogram))
	for s := range histogram {
		sizes = append(sizes, s)
	}
	sort.Ints(sizes)
	for _, s := range sizes {
		fmt.Fprintf(out, "  %d entry: %d\n", s, histogram[s])
	}

	if len(ecoCounts) > 0 {
		fmt.Fprintln(out, "OSV by ecosystem:")
		ecos := make([]string, 0, len(ecoCounts))
		for e := range ecoCounts {
			ecos = append(ecos, e)
		}
		sort.Strings(ecos)
		for _, e := range ecos {
			fmt.Fprintf(out, "  %s: %d\n", e, ecoCounts[e])
		}
	}
}
