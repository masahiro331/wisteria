package debug

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/masahiro331/wisteria/internal/unified/unifier"
	"github.com/masahiro331/wisteria/internal/unified/walker"
	"github.com/masahiro331/wisteria/internal/x/cachedir"
)

// newUnifyCmd returns `wisteria debug unify`. The --id flag selects one
// PrimaryID, runs walker.Index, then full-parses each IndexEntry under
// that id and applies the §16 merge rules (References + Severities).
// Output is the merged UnifiedAdvisory as indented JSON on stdout.
//
// Descriptions / Affected / SourceIDs / KEV / EPSS are not yet populated
// — those land in #17 / #20 / #21. Today's debug output exists to
// validate the §8.2 / §8.4 rules against real source files.
func newUnifyCmd() *cobra.Command {
	var id string
	c := &cobra.Command{
		Use:   "unify",
		Short: "Run mergeReferences + mergeSeverities for one PrimaryID and emit JSON",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if id == "" {
				return errors.New("--id is required")
			}
			cacheDirOverride, _ := cmd.Flags().GetString("cache-dir")
			root, err := cachedir.Root(cacheDirOverride)
			if err != nil {
				return err
			}
			sourcesRoot := filepath.Join(root, cachedir.SourcesSubdir)

			idx, err := walker.Index(cmd.Context(), sourcesRoot)
			if err != nil {
				return fmt.Errorf("walker.Index: %w", err)
			}
			entries, ok := idx[id]
			if !ok {
				return fmt.Errorf("PrimaryID %q not found in index", id)
			}
			advisory, err := unifier.MergePrimary(cmd.Context(), sourcesRoot, id, entries)
			if err != nil {
				return err
			}
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			return enc.Encode(advisory)
		},
	}
	c.Flags().StringVar(&id, "id", "", "PrimaryID (CVE-ID or source-derived id) to merge")
	return c
}
