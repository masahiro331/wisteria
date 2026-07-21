package annotator

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/masahiro331/wisteria/internal/unified/writer"
	"github.com/masahiro331/wisteria/pkg/advisory"
)

// updateCVE is the shared apply skeleton of every annotator: resolve
// the unified file for one CVE-ID, load it, let mutate set the signal
// field, and rewrite the file. A non-CVE id or a missing unified file
// is a silent skip (see package doc) — mutate only runs on a hit.
func updateCVE(outDir, cveID string, mutate func(*advisory.UnifiedAdvisory)) error {
	path, ok := writer.CVEPath(outDir, cveID)
	if !ok {
		return nil
	}
	rec, ok, err := readUnified(path)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	mutate(&rec)
	return writeUnified(path, rec)
}

// readUnified loads one Stage 3 file. (_, false, nil) means the file is
// absent — the caller skips. Any other I/O or decode error is returned.
func readUnified(path string) (advisory.UnifiedAdvisory, bool, error) {
	body, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return advisory.UnifiedAdvisory{}, false, nil
	}
	if err != nil {
		return advisory.UnifiedAdvisory{}, false, fmt.Errorf("annotator: read %s: %w", path, err)
	}
	var rec advisory.UnifiedAdvisory
	if err := json.Unmarshal(body, &rec); err != nil {
		return advisory.UnifiedAdvisory{}, false, fmt.Errorf("annotator: decode %s: %w", path, err)
	}
	return rec, true, nil
}

// writeUnified rewrites a Stage 3 file in place. Plain os.WriteFile —
// not atomic — because Stage 4 always runs as part of `wisteria unify`
// after Stage 3, so a crashed mid-write file is rebuilt on the next
// pipeline run from upstream sources (which the user keeps under git).
func writeUnified(path string, rec advisory.UnifiedAdvisory) error {
	body, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return fmt.Errorf("annotator: marshal %s: %w", path, err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		return fmt.Errorf("annotator: write %s: %w", path, err)
	}
	return nil
}
