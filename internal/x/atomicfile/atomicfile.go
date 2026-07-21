// Package atomicfile writes files atomically via temp + rename in the
// destination directory, so readers never observe a partially written
// file. Shared by Stage 3 (writer) and Stage 5 (indexer), whose output
// trees are read concurrently by pkg/db drivers.
package atomicfile

import (
	"fmt"
	"os"
	"path/filepath"
)

// Write persists body at path atomically. The parent directory must
// already exist — callers own directory creation (and its caching).
// The temp file inherits os.CreateTemp's 0600 mode.
func Write(path string, body []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("atomicfile: temp file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("atomicfile: write %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("atomicfile: close %s: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("atomicfile: rename %s -> %s: %w", tmpName, path, err)
	}
	return nil
}
