package debug

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sort"

	"github.com/spf13/cobra"

	"github.com/masahiro331/wisteria/internal/unified"
	"github.com/masahiro331/wisteria/internal/unified/unifier"
	"github.com/masahiro331/wisteria/internal/unified/walker"
	"github.com/masahiro331/wisteria/internal/x/cachedir"
)

// newUnifyCmd returns `wisteria debug unify`. It runs walker.Index then
// unifier.MergePrimary on either one PrimaryID (--id, indented JSON
// output) or the lex-sorted first N PrimaryIDs (--sample N, NDJSON
// output). The --sample mode exists for §8 merge-rule validation against
// real data — the lex-sorted slice is reproducible across runs so a
// reviewer can pin findings to specific PrimaryIDs.
//
// --id and --sample are mutually exclusive; one is required.
func newUnifyCmd() *cobra.Command {
	var (
		id         string
		sampleSize int
	)
	c := &cobra.Command{
		Use:   "unify",
		Short: "Merge one PrimaryID (--id) or the first N (--sample) and emit JSON",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if id == "" && sampleSize <= 0 {
				return errors.New("one of --id or --sample N is required")
			}
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

			out := cmd.OutOrStdout()
			if id != "" {
				return runOneID(cmd.Context(), out, sourcesRoot, id, idx)
			}
			return runSample(cmd.Context(), out, sourcesRoot, sampleSize, idx)
		},
	}
	c.Flags().StringVar(&id, "id", "", "PrimaryID (CVE-ID or source-derived id) to merge")
	c.Flags().IntVar(&sampleSize, "sample", 0, "merge the lex-sorted first N PrimaryIDs and emit NDJSON (for §8 merge-rule validation)")
	c.MarkFlagsMutuallyExclusive("id", "sample")
	return c
}

// runOneID merges one PrimaryID and emits indented JSON. Returns
// (PrimaryID-not-found) as a non-zero exit so shell pipelines can branch
// on existence without parsing stdout.
func runOneID(ctx context.Context, out io.Writer, sourcesRoot, id string, idx map[string][]unified.IndexEntry) error {
	entries, ok := idx[id]
	if !ok {
		return fmt.Errorf("PrimaryID %q not found in index", id)
	}
	advisory, err := unifier.MergePrimary(ctx, sourcesRoot, id, entries)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(advisory)
}

// runSample merges the lex-sorted first n PrimaryIDs and emits NDJSON
// (one minified record per line). NDJSON keeps the output greppable /
// jq-streamable, which matters for the validation use case where the
// reviewer pipes 50+ records through jq filters.
func runSample(ctx context.Context, out io.Writer, sourcesRoot string, n int, idx map[string][]unified.IndexEntry) error {
	ids := make([]string, 0, len(idx))
	for k := range idx {
		ids = append(ids, k)
	}
	sort.Strings(ids)
	if n > len(ids) {
		n = len(ids)
	}
	enc := json.NewEncoder(out) // no indent → one line per record
	for _, id := range ids[:n] {
		if err := ctx.Err(); err != nil {
			return err
		}
		advisory, err := unifier.MergePrimary(ctx, sourcesRoot, id, idx[id])
		if err != nil {
			return fmt.Errorf("merge %s: %w", id, err)
		}
		if err := enc.Encode(advisory); err != nil {
			return fmt.Errorf("encode %s: %w", id, err)
		}
	}
	return nil
}
