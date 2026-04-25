// Package writer is Stage 3 of the unified-advisory pipeline. It writes
// one JSON file per UnifiedAdvisory under <cacheDir>/unified/, following
// design §4 / §9:
//
//   - PrimaryID == CVE-YYYY-NNNN  →  cve/<YYYY>/<PrimaryID>.json
//   - else                        →  standalone/<ecosystem>/<PrimaryID>.json
//
// The package exposes two functions and no state:
//
//   - Init(cacheDir)                – guard the deletion target, return outDir.
//     Caller (cmd/unify) is responsible for
//     RemoveAll + MkdirAll on outDir before
//     calling Write.
//   - Write(outDir, rec)            – marshal one record + temp + rename.
//     Safe for concurrent use; bucket dirs
//     are MkdirAll'd lazily and cached so
//     N records into the same year/eco
//     bucket trigger one mkdir, not N.
//
// Splitting Init from Write lets the production driver stream merge
// output straight to disk (one record per goroutine) instead of holding
// the entire []UnifiedAdvisory in memory.
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

	"github.com/masahiro331/wisteria/internal/unified"
	"github.com/masahiro331/wisteria/internal/unified/unifier"
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

// Init validates cacheDir, derives outDir = <cacheDir>/unified, and
// returns it. It does NOT delete or create outDir — the caller is
// expected to do RemoveAll + MkdirAll before streaming Write calls.
// The split exists so per-record fan-out can run without coordinating
// the one-shot tree reset.
func Init(cacheDir string) (string, error) {
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

// Write serializes one record to its bucket-derived path under outDir.
// The bucket directory is MkdirAll'd lazily on first use (cached for
// the life of the process) so concurrent callers writing into the same
// bucket pay the syscall cost once. Per-file atomic via temp + rename.
func Write(outDir string, rec unified.UnifiedAdvisory) error {
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
// to cve/<year>/; everything else goes to standalone/<ecosystem>/, where
// ecosystem comes from the highest-priority OSV provenance.
func bucketPath(outDir string, rec unified.UnifiedAdvisory) (dir, file string, err error) {
	safeName := escapeFilename(rec.PrimaryID) + ".json"
	if m := cveIDPattern.FindStringSubmatch(rec.PrimaryID); m != nil {
		return filepath.Join(outDir, cveBucket, m[1]), safeName, nil
	}
	eco, err := primaryEcosystem(rec.Provenances)
	if err != nil {
		return "", "", fmt.Errorf("writer: %s: %w", rec.PrimaryID, err)
	}
	return filepath.Join(outDir, standaloneBucket, eco), safeName, nil
}

// primaryEcosystem picks the OSV provenance with the lowest PriorityRank.
// Standalone PrimaryIDs come from OSV by definition (no CVE-ID alias), so
// missing OSV here is an upstream bug in the index; we surface it as an
// error rather than silently defaulting to a fallback bucket.
func primaryEcosystem(provs []unified.Provenance) (string, error) {
	bestRank := -1
	best := ""
	for _, p := range provs {
		if p.Kind != unified.SourceOSV {
			continue
		}
		eco := osvEcosystem(p.Path)
		if eco == "" {
			continue
		}
		rank := unifier.PriorityRank(unifier.SourceTag(unified.SourceOSV, eco))
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
func osvEcosystem(provPath string) string {
	parts := strings.Split(provPath, "/")
	if len(parts) < 2 || parts[0] != "osv" {
		return ""
	}
	return parts[1]
}

// escapeFilename replaces filesystem-unsafe characters in a PrimaryID.
// Targets are `/` and `:` per design §9; both become "_".
func escapeFilename(id string) string {
	id = strings.ReplaceAll(id, "/", unsafeFilenameRep)
	id = strings.ReplaceAll(id, ":", unsafeFilenameRep)
	return id
}
