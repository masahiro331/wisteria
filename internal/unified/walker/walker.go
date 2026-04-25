// Package walker is Stage 1 of the unified-advisory pipeline. It walks
// the per-source download tree (<sourcesRoot>/osv/... and
// <sourcesRoot>/cve/cvelistV5-main/cves/...) and returns the index that
// Stage 2 (unifier) needs: PrimaryID -> []IndexEntry.
//
// PrimaryID resolution follows design §3.1:
//
//   - CVE5 file: PrimaryID = filename CVE-ID. Body is not read.
//   - OSV file with N CVE-ID aliases: file is duplicated under each CVE-ID
//     PrimaryID. (Same file path, same SourceID — Stage 2 sees both copies.)
//   - OSV file without any CVE-ID alias: PrimaryID = OSV `id` (standalone).
//
// KEV / EPSS are handled in Stage 4 (annotator), not here.
//
// Error policy: any unreadable / malformed advisory file aborts the whole
// walk. The index is intermediate state — re-running is cheap, so failing
// loud beats silently dropping records.
package walker

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/masahiro331/wisteria/internal/unified"
)

// osvLite is the smallest OSV shape that PrimaryID resolution needs.
// Reading more here would force every advisory to fully unmarshal during
// Stage 1, which is exactly what design §5 (Stage 1 reads only `id` and
// `aliases`) is trying to avoid.
type osvLite struct {
	ID      string   `json:"id"`
	Aliases []string `json:"aliases"`
}

// Index walks <sourcesRoot> and returns PrimaryID -> []IndexEntry.
//
// The map's value list preserves the order in which entries were observed
// during the walk (filepath.WalkDir's lexical order); callers that need a
// stable cross-source ordering must sort themselves. Sequential walk by
// design — concurrency is decided in a follow-up issue.
func Index(ctx context.Context, sourcesRoot string) (map[string][]unified.IndexEntry, error) {
	if _, err := os.Stat(sourcesRoot); err != nil {
		return nil, fmt.Errorf("walker: stat sources root: %w", err)
	}

	out := make(map[string][]unified.IndexEntry)

	if err := walkOSV(ctx, sourcesRoot, out); err != nil {
		return nil, err
	}
	if err := walkCVE(ctx, sourcesRoot, out); err != nil {
		return nil, err
	}
	return out, nil
}

func walkOSV(ctx context.Context, sourcesRoot string, out map[string][]unified.IndexEntry) error {
	osvRoot := filepath.Join(sourcesRoot, "osv")
	if _, err := os.Stat(osvRoot); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return fmt.Errorf("walker: stat osv root: %w", err)
	}
	// Open a root-scoped handle so the per-file ReadFile below cannot
	// follow a symlink out of <sourcesRoot>/osv. Defends against an
	// adversarially-prepared download tree.
	rootFS, err := os.OpenRoot(osvRoot)
	if err != nil {
		return fmt.Errorf("walker: open osv root: %w", err)
	}
	defer rootFS.Close()

	return filepath.WalkDir(osvRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".json") {
			return nil
		}
		// Skip symlinks / sockets / fifos. Source trees are populated by
		// the fetcher (zip / tar.gz extraction), neither of which should
		// produce non-regular entries.
		if !d.Type().IsRegular() {
			return nil
		}

		// Ecosystem = directory name immediately under osv/. Per design
		// §4, the ecosystem name is preserved verbatim (including spaces
		// like "Rocky Linux"); we do not normalize here.
		rel, err := filepath.Rel(osvRoot, path)
		if err != nil {
			return fmt.Errorf("walker: rel %s: %w", path, err)
		}
		parts := strings.Split(rel, string(filepath.Separator))
		if len(parts) < 2 {
			// File directly under osv/ with no ecosystem dir. Shouldn't
			// happen in fetcher output, but treat as skip rather than
			// crash — the body parse below would still succeed.
			return nil
		}
		ecosystem := parts[0]

		body, err := rootFS.ReadFile(rel)
		if err != nil {
			return fmt.Errorf("walker: read %s: %w", path, err)
		}
		var rec osvLite
		if err := json.Unmarshal(body, &rec); err != nil {
			return fmt.Errorf("walker: parse %s: %w", path, err)
		}
		if rec.ID == "" {
			return fmt.Errorf("walker: %s: missing id", path)
		}

		relFromSources, err := filepath.Rel(sourcesRoot, path)
		if err != nil {
			return fmt.Errorf("walker: rel sources %s: %w", path, err)
		}

		entry := unified.IndexEntry{
			Path:     relFromSources,
			Kind:     unified.SourceOSV,
			Source:   ecosystem,
			SourceID: rec.ID,
		}

		cves := cveAliases(rec.Aliases)
		if len(cves) == 0 {
			out[rec.ID] = append(out[rec.ID], entry)
			return nil
		}
		for _, cve := range cves {
			out[cve] = append(out[cve], entry)
		}
		return nil
	})
}

func walkCVE(ctx context.Context, sourcesRoot string, out map[string][]unified.IndexEntry) error {
	// Walk only the catalog subtree (design §4). The upstream cvelistV5
	// repo also ships fixtures / examples named CVE-*.json under
	// tests/, schemas/, etc. — those are not real advisories and would
	// pollute the index if we walked the whole `cve/` tree.
	cveRoot := filepath.Join(sourcesRoot, "cve", "cvelistV5-main", "cves")
	if _, err := os.Stat(cveRoot); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return fmt.Errorf("walker: stat cve root: %w", err)
	}

	return filepath.WalkDir(cveRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		base := filepath.Base(path)
		// CVE5 advisory filenames are CVE-YYYY-NNNN.json. Anything else
		// (delta.json, deltaLog.json, README.md, ...) is repo metadata
		// from cvelistV5 itself — skip it.
		if !strings.HasPrefix(base, "CVE-") || !strings.HasSuffix(base, ".json") {
			return nil
		}
		// Skip symlinks / sockets / fifos. Stage 2 reopens IndexEntry.Path
		// via filepath.Join(sourcesRoot, Path), which would happily follow
		// a CVE-named symlink out of the sources tree. Mirrors the OSV
		// regular-file guard above.
		if !d.Type().IsRegular() {
			return nil
		}
		cveID := strings.TrimSuffix(base, ".json")

		relFromSources, err := filepath.Rel(sourcesRoot, path)
		if err != nil {
			return fmt.Errorf("walker: rel sources %s: %w", path, err)
		}
		out[cveID] = append(out[cveID], unified.IndexEntry{
			Path:     relFromSources,
			Kind:     unified.SourceCVE,
			Source:   "",
			SourceID: cveID,
		})
		return nil
	})
}

// cveAliases returns the subset of `aliases` that look like CVE-IDs,
// preserving order. Anything else (GHSA-, PYSEC-, ALBA-, ...) is a
// SourceID-side identifier, handled in Stage 2 when SourceIDs are built.
func cveAliases(aliases []string) []string {
	var out []string
	for _, a := range aliases {
		if strings.HasPrefix(a, "CVE-") {
			out = append(out, a)
		}
	}
	return out
}
