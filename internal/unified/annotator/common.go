package annotator

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/masahiro331/wisteria/internal/unified"
)

// readUnified loads one Stage 3 file. (_, false, nil) means the file is
// absent — the caller skips. Any other I/O or decode error is returned.
func readUnified(path string) (unified.UnifiedAdvisory, bool, error) {
	body, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return unified.UnifiedAdvisory{}, false, nil
	}
	if err != nil {
		return unified.UnifiedAdvisory{}, false, fmt.Errorf("annotator: read %s: %w", path, err)
	}
	var rec unified.UnifiedAdvisory
	if err := json.Unmarshal(body, &rec); err != nil {
		return unified.UnifiedAdvisory{}, false, fmt.Errorf("annotator: decode %s: %w", path, err)
	}
	return rec, true, nil
}

// writeUnified rewrites a Stage 3 file in place. Plain os.WriteFile —
// not atomic — because Stage 4 always runs as part of `wisteria unify`
// after Stage 3, so a crashed mid-write file is rebuilt on the next
// pipeline run from upstream sources (which the user keeps under git).
func writeUnified(path string, rec unified.UnifiedAdvisory) error {
	body, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return fmt.Errorf("annotator: marshal %s: %w", path, err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		return fmt.Errorf("annotator: write %s: %w", path, err)
	}
	return nil
}
