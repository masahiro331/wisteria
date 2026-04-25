// Package cachedir resolves the local directory wisteria writes downloaded
// data into. It is path resolution only — there is no eviction or in-memory
// tier; the name reflects the on-disk cache location, not a cache layer API.
package cachedir

import (
	"fmt"
	"os"
	"path/filepath"
)

const (
	appName = "wisteria"
	// EnvCacheDir lets users override the cache directory root via environment.
	EnvCacheDir = "WISTERIA_CACHE_DIR"
)

// Root resolves the wisteria cache directory root using this precedence:
//  1. override (typically a CLI flag value)
//  2. WISTERIA_CACHE_DIR environment variable
//  3. os.UserCacheDir()/wisteria
//
// The returned directory is created if it does not exist.
func Root(override string) (string, error) {
	root, err := resolveRoot(override)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(root, 0o750); err != nil {
		return "", fmt.Errorf("create cache dir %s: %w", root, err)
	}
	return root, nil
}

// SourcesSubdir is the subdirectory under Root that holds raw downloads.
// The unified pipeline writes its output to a sibling subdirectory.
const SourcesSubdir = "sources"

// Dir resolves a per-source cache directory under Root/sources and creates it.
func Dir(override, source string) (string, error) {
	root, err := Root(override)
	if err != nil {
		return "", err
	}
	dir := filepath.Join(root, SourcesSubdir, source)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", fmt.Errorf("create cache dir %s: %w", dir, err)
	}
	return dir, nil
}

func resolveRoot(override string) (string, error) {
	if override != "" {
		return override, nil
	}
	if env := os.Getenv(EnvCacheDir); env != "" {
		return env, nil
	}
	base, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("resolve user cache dir: %w", err)
	}
	return filepath.Join(base, appName), nil
}
