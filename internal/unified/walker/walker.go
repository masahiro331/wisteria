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
	"sort"
	"strings"
	"sync"

	"golang.org/x/sync/errgroup"

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
// OSV body parsing fans out via a worker pool whose size is set by
// WithConcurrency (default 4× NumCPU; I/O-bound). The walk itself
// (filepath.WalkDir) and the per-PrimaryID merge into the result map
// stay single-threaded so the map needs no lock and the entry order
// inside each list remains lexical-by-path.
//
// Callers that need a stable cross-source ordering inside one PrimaryID
// must sort themselves; this function only guarantees that the same
// input tree produces an equal map regardless of concurrency.
func Index(ctx context.Context, sourcesRoot string, opts ...Option) (map[string][]unified.IndexEntry, error) {
	if _, err := os.Stat(sourcesRoot); err != nil {
		return nil, fmt.Errorf("walker: stat sources root: %w", err)
	}
	cfg := newConfig(opts)

	out := make(map[string][]unified.IndexEntry)

	if err := walkOSV(ctx, sourcesRoot, out, cfg.concurrency); err != nil {
		return nil, err
	}
	if err := walkCVE(ctx, sourcesRoot, out); err != nil {
		return nil, err
	}
	return out, nil
}

// osvParseResult is what the parallel parser hands back to the main
// goroutine for inclusion in the index. primaryIDs is pre-resolved
// (each CVE-alias produces one entry; standalone records produce one
// entry under their own id) so the main-side merge stays trivial.
type osvParseResult struct {
	entry      unified.IndexEntry
	primaryIDs []string
}

// osvParseJob is the immutable per-file context handed from the WalkDir
// goroutine to the worker pool: relative path under osvRoot for the
// fenced ReadFile, the source-root-relative path that ends up in
// IndexEntry, the absolute path used in error messages, and the
// pre-extracted ecosystem segment.
type osvParseJob struct {
	relUnderOSV    string
	relFromSources string
	absPath        string
	ecosystem      string
}

func walkOSV(ctx context.Context, sourcesRoot string, out map[string][]unified.IndexEntry, concurrency int) error {
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

	// Stage A: enumerate candidate files (single-threaded WalkDir).
	// Stage B: ReadFile + json.Unmarshal in a bounded worker pool.
	// Stage C: merge worker output into `out` in lexical order so the
	// per-PrimaryID entry list matches the sequential walker exactly.
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(concurrency)

	results := make(chan osvParseResult, concurrency*2)
	var (
		mergeWG sync.WaitGroup
		buffer  []osvParseResult
	)
	mergeWG.Go(func() {
		for r := range results {
			buffer = append(buffer, r)
		}
	})

	walkErr := filepath.WalkDir(osvRoot, func(path string, d fs.DirEntry, err error) error {
		job, skip, err := osvWalkStep(gctx, sourcesRoot, osvRoot, path, d, err)
		if err != nil || skip {
			return err
		}
		g.Go(func() error {
			return parseOSVFile(gctx, rootFS, job, results)
		})
		return nil
	})

	// Wait for all workers, then close the channel so the merger drains.
	groupErr := g.Wait()
	close(results)
	mergeWG.Wait()

	// Prefer groupErr: when a worker returns a parse error the errgroup
	// cancels gctx, which then surfaces as context.Canceled inside the
	// WalkDir callback (osvWalkStep checks gctx). Returning walkErr
	// first would mask the real "walker: parse foo.json: ..." with a
	// generic "context canceled" and lose the file path.
	if groupErr != nil {
		return groupErr
	}
	if walkErr != nil {
		return walkErr
	}

	// Restore lexical order: WalkDir dispatched in path order but workers
	// finish in arbitrary order. Sorting by entry.Path reconstructs the
	// sequential walker's per-PrimaryID entry order.
	sort.SliceStable(buffer, func(i, j int) bool {
		return buffer[i].entry.Path < buffer[j].entry.Path
	})
	for _, r := range buffer {
		for _, pid := range r.primaryIDs {
			out[pid] = append(out[pid], r.entry)
		}
	}
	return nil
}

// osvWalkStep is the WalkDir-callback half of the OSV walk: filter +
// path math only, no I/O. Returns (job, skip=true) for entries that the
// walker should ignore (dirs, non-.json, non-regular, files lacking an
// ecosystem dir). Errors short-circuit the walk.
func osvWalkStep(ctx context.Context, sourcesRoot, osvRoot, path string, d fs.DirEntry, walkErr error) (osvParseJob, bool, error) {
	if walkErr != nil {
		return osvParseJob{}, true, walkErr
	}
	if err := ctx.Err(); err != nil {
		return osvParseJob{}, true, err
	}
	if d.IsDir() || !strings.HasSuffix(path, ".json") {
		return osvParseJob{}, true, nil
	}
	// Skip symlinks / sockets / fifos. Source trees are populated by
	// the fetcher (zip / tar.gz extraction), neither of which should
	// produce non-regular entries.
	if !d.Type().IsRegular() {
		return osvParseJob{}, true, nil
	}
	rel, err := filepath.Rel(osvRoot, path)
	if err != nil {
		return osvParseJob{}, true, fmt.Errorf("walker: rel %s: %w", path, err)
	}
	parts := strings.Split(rel, string(filepath.Separator))
	if len(parts) < 2 {
		// File directly under osv/ with no ecosystem dir. Shouldn't
		// happen in fetcher output, but treat as skip rather than crash.
		return osvParseJob{}, true, nil
	}
	relFromSources, err := filepath.Rel(sourcesRoot, path)
	if err != nil {
		return osvParseJob{}, true, fmt.Errorf("walker: rel sources %s: %w", path, err)
	}
	return osvParseJob{
		relUnderOSV:    rel,
		relFromSources: relFromSources,
		absPath:        path,
		ecosystem:      strings.ReplaceAll(parts[0], " ", "_"),
	}, false, nil
}

// parseOSVFile is the worker-pool half: ReadFile + json.Unmarshal +
// PrimaryID resolution. Sends one osvParseResult per file into results,
// or returns the parse error so the errgroup can cancel siblings.
func parseOSVFile(ctx context.Context, rootFS *os.Root, job osvParseJob, results chan<- osvParseResult) error {
	body, err := rootFS.ReadFile(job.relUnderOSV)
	if err != nil {
		return fmt.Errorf("walker: read %s: %w", job.absPath, err)
	}
	var rec osvLite
	if err := json.Unmarshal(body, &rec); err != nil {
		return fmt.Errorf("walker: parse %s: %w", job.absPath, err)
	}
	if rec.ID == "" {
		return fmt.Errorf("walker: %s: missing id", job.absPath)
	}
	entry := unified.IndexEntry{
		Path:     job.relFromSources,
		Kind:     unified.SourceOSV,
		Source:   job.ecosystem,
		SourceID: rec.ID,
	}
	pids := cveAliases(rec.Aliases)
	if len(pids) == 0 {
		pids = []string{rec.ID}
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case results <- osvParseResult{entry: entry, primaryIDs: pids}:
		return nil
	}
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
