// Package writer is Stage 3 of the unified-advisory pipeline. It writes
// one JSON file per UnifiedAdvisory under <cacheDir>/unified/, following
// design §4 / §9:
//
//   - PrimaryID == CVE-YYYY-NNNN  →  cve/<YYYY>/<PrimaryID>.json
//   - else                        →  standalone/<ecosystem>/<PrimaryID>.json
//
// Public API:
//
//   - OutDir(cacheDir)    – derive the unified output path; no I/O.
//     Used by read-only callers (annotator, debug
//     tools) that just need the path.
//   - Init(cacheDir)      – validate the destination + clear the bucket
//     mkdir cache; returns outDir without touching
//     the tree. Caller is then responsible for
//     RemoveAll + MkdirAll before streaming Write.
//   - Reset(cacheDir)     – Init + RemoveAll + MkdirAll in one call;
//     the entrypoint cmd/unify uses to start a
//     fresh write fan-out.
//   - Write(outDir, rec)  – marshal one record + temp + rename. Safe for
//     concurrent use; bucket dirs are MkdirAll'd
//     lazily and cached (package-level sync.Map,
//     reset on every Init/Reset) so N records into
//     the same year/eco bucket trigger one mkdir.
//   - CVEPath(outDir, id) – resolve the per-record path for one CVE-ID,
//     used by Stage 4 (annotator) so the year-bucket
//     routing stays defined here.
//
// Splitting Init/Reset from Write lets the production driver stream
// merge output straight to disk (one record per goroutine) instead of
// holding the entire []UnifiedAdvisory in memory.
package writer

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/masahiro331/wisteria/internal/unified/unifier"
	"github.com/masahiro331/wisteria/pkg/advisory"
)

const (
	outSubdir         = "unified"
	cveBucket         = "cve"
	standaloneBucket  = "standalone"
	unsafeFilenameRep = "_"
)

// cveIDPattern is the design §4 PrimaryID shape that routes to the cve
// bucket. The capture group exposes the year for the directory split.
var cveIDPattern = regexp.MustCompile(`^CVE-(\d{4})-\d+$`)

// bucketMkdir caches "this bucket dir already exists" so a fan-out of
// 100k+ writes into the same cve/2024/ doesn't hit MkdirAll 100k times.
// Keyed by absolute bucket path.
var bucketMkdir sync.Map // map[string]struct{}

// OutDir derives the unified output directory from cacheDir without
// touching the filesystem. Read-only callers (annotator, debug tools)
// use this when they only need the path, not the destination guard
// or the tree reset that Init / Reset perform.
func OutDir(cacheDir string) (string, error) {
	if cacheDir == "" {
		return "", errors.New("writer: cacheDir is empty")
	}
	abs, err := filepath.Abs(cacheDir)
	if err != nil {
		return "", fmt.Errorf("writer: resolve cacheDir %q: %w", cacheDir, err)
	}
	cleaned := filepath.Clean(abs)
	if cleaned == string(filepath.Separator) {
		return "", fmt.Errorf("writer: cacheDir %q resolves to filesystem root", cacheDir)
	}
	outDir := filepath.Join(cleaned, outSubdir)
	if filepath.Base(outDir) != outSubdir {
		return "", fmt.Errorf("writer: derived outDir %q does not end in %q", outDir, outSubdir)
	}
	return outDir, nil
}

// Init validates cacheDir, derives outDir = <cacheDir>/unified, and
// returns it. It does NOT delete or create outDir — the caller is
// expected to do RemoveAll + MkdirAll before streaming Write calls,
// or call Reset to do both in one step.
// The split exists so per-record fan-out can run without coordinating
// the one-shot tree reset.
//
// Init also clears the package-level bucket-mkdir cache: a second call
// in the same process means the caller is about to RemoveAll outDir,
// and a stale cache hit would skip the MkdirAll on the next Write and
// then fail at CreateTemp on a missing parent.
func Init(cacheDir string) (string, error) {
	bucketMkdir.Clear()
	outDir, err := OutDir(cacheDir)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(outDir)
	switch {
	case os.IsNotExist(err):
		return outDir, nil
	case err != nil:
		return "", fmt.Errorf("writer: stat %s: %w", outDir, err)
	case info.Mode()&os.ModeSymlink != 0:
		return "", fmt.Errorf("writer: %s is a symlink, refusing to use", outDir)
	case !info.IsDir():
		return "", fmt.Errorf("writer: %s is not a directory, refusing to use", outDir)
	}
	return outDir, nil
}

// Reset runs Init, then RemoveAll + MkdirAll on the resulting outDir so
// callers (cmd/unify) can start a fresh write fan-out in one call. The
// guard inside Init keeps the destruction target bounded to a wisteria
// "unified" subdirectory.
func Reset(cacheDir string) (string, error) {
	outDir, err := Init(cacheDir)
	if err != nil {
		return "", err
	}
	if err := os.RemoveAll(outDir); err != nil {
		return "", fmt.Errorf("writer: clear %s: %w", outDir, err)
	}
	if err := os.MkdirAll(outDir, 0o750); err != nil {
		return "", fmt.Errorf("writer: recreate %s: %w", outDir, err)
	}
	return outDir, nil
}

// CVEPath returns the per-record unified path for a CVE-ID under outDir,
// matching the routing Write applies. (_, false) means the ID is not a
// CVE-YYYY-NNNN that Stage 3 routes to cve/<year>/. Annotator and debug
// tools use this so the year-bucket policy stays defined in one place.
func CVEPath(outDir, cveID string) (string, bool) {
	m := cveIDPattern.FindStringSubmatch(cveID)
	if m == nil {
		return "", false
	}
	return filepath.Join(outDir, cveBucket, m[1], cveID+".json"), true
}

// Write serializes one record to its bucket-derived path under outDir.
// The bucket directory is MkdirAll'd lazily on first use (cached for
// the life of the process) so concurrent callers writing into the same
// bucket pay the syscall cost once. Per-file atomic via temp + rename.
func Write(outDir string, rec advisory.UnifiedAdvisory) error {
	dir, file, err := bucketPath(outDir, rec)
	if err != nil {
		return err
	}
	if err := ensureDir(dir); err != nil {
		return err
	}
	body, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return fmt.Errorf("writer: marshal %s: %w", rec.PrimaryID, err)
	}
	final := filepath.Join(dir, file)
	tmp, err := os.CreateTemp(dir, ".write-*")
	if err != nil {
		return fmt.Errorf("writer: temp file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("writer: write %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("writer: close %s: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, final); err != nil {
		return fmt.Errorf("writer: rename %s -> %s: %w", tmpName, final, err)
	}
	return nil
}

func ensureDir(dir string) error {
	if _, ok := bucketMkdir.Load(dir); ok {
		return nil
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("writer: mkdir %s: %w", dir, err)
	}
	bucketMkdir.Store(dir, struct{}{})
	return nil
}

// bucketPath returns the directory + filename for one record. CVE-IDs go
// to cve/<year>/ (delegated to CVEPath so the routing rule lives in one
// place); everything else goes to standalone/<ecosystem>/, where
// ecosystem comes from the highest-priority OSV provenance.
func bucketPath(outDir string, rec advisory.UnifiedAdvisory) (dir, file string, err error) {
	if path, ok := CVEPath(outDir, rec.PrimaryID); ok {
		return filepath.Dir(path), filepath.Base(path), nil
	}
	eco, err := primaryEcosystem(rec.Provenances)
	if err != nil {
		return "", "", fmt.Errorf("writer: %s: %w", rec.PrimaryID, err)
	}
	return filepath.Join(outDir, standaloneBucket, eco), escapeFilename(rec.PrimaryID) + ".json", nil
}

// primaryEcosystem picks the OSV provenance with the lowest PriorityRank.
// Standalone PrimaryIDs come from OSV by definition (no CVE-ID alias), so
// missing OSV here is an upstream bug in the index; we surface it as an
// error rather than silently defaulting to a fallback bucket.
func primaryEcosystem(provs []advisory.Provenance) (string, error) {
	bestRank := -1
	best := ""
	for _, p := range provs {
		if p.Kind != advisory.SourceOSV {
			continue
		}
		eco := osvEcosystem(p.Path)
		if eco == "" {
			continue
		}
		rank := unifier.PriorityRank(unifier.SourceTag(advisory.SourceOSV, eco))
		if best == "" || rank < bestRank {
			best = eco
			bestRank = rank
		}
	}
	if best == "" {
		return "", errors.New("standalone advisory has no OSV provenance to derive ecosystem")
	}
	return best, nil
}

// osvEcosystem extracts the ecosystem directory name from an OSV
// provenance path of the shape "osv/<eco>/<file>.json". walker.Index
// guarantees this layout when Kind is SourceOSV.
//
// Spaces are normalized to "_" to match the form walker stores in
// IndexEntry.Source and the form the priority array uses (e.g.
// "Red Hat" → "Red_Hat"). Without this, the SourceTag below would miss
// the priority table for any multi-word ecosystem and route those
// records to the wrong standalone bucket.
func osvEcosystem(provPath string) string {
	parts := strings.Split(provPath, "/")
	if len(parts) < 2 || parts[0] != "osv" {
		return ""
	}
	return strings.ReplaceAll(parts[1], " ", "_")
}

// escapeFilename replaces filesystem-unsafe characters in a PrimaryID.
// Targets are `/` and `:` per design §9; both become "_".
func escapeFilename(id string) string {
	id = strings.ReplaceAll(id, "/", unsafeFilenameRep)
	id = strings.ReplaceAll(id, ":", unsafeFilenameRep)
	return id
}
