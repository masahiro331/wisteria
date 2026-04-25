// Package fetcher defines the contract for vulnerability data sources.
package fetcher

import "context"

// Fetcher downloads vulnerability data from a source and persists it locally.
// Implementations are responsible for choosing where to write under the
// wisteria cache directory.
type Fetcher interface {
	// Name returns the source identifier (e.g. "osv", "cve").
	Name() string
	// Fetch downloads the dataset and reports the directory it was written to.
	Fetch(ctx context.Context) (dir string, err error)
}
