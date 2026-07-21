// Package epss fetches the FIRST EPSS daily score catalog. Single-file
// HTTP download; the flow lives in fetcher.Catalog, this package owns
// the EPSS defaults, options, and the gzip-decompressing write step.
package epss

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/masahiro331/wisteria/internal/fetcher"
	"github.com/masahiro331/wisteria/internal/fetcher/progress"
)

const (
	sourceName        = "epss"
	defaultCatalogURL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
	catalogFilename   = "epss_scores-current.csv"
)

// maxDecompressedBytes caps the gzip-decoded payload size to defend against
// decompression bombs. The current EPSS daily CSV is ~14MB; 100MB leaves
// generous headroom for years of growth.
var maxDecompressedBytes int64 = 100 * 1024 * 1024

// Option configures a Fetcher.
type Option func(*Fetcher)

// WithCatalogURL overrides the upstream catalog URL.
func WithCatalogURL(u string) Option { return func(f *Fetcher) { f.catalog.URL = u } }

// WithHTTPClient injects a custom HTTP client.
func WithHTTPClient(c *http.Client) Option { return func(f *Fetcher) { f.catalog.Client = c } }

// WithCacheDir overrides the cache root used to store downloads.
func WithCacheDir(dir string) Option { return func(f *Fetcher) { f.catalog.CacheDir = dir } }

// WithProgress attaches a progress tracker. A nil tracker disables progress UI.
func WithProgress(t *progress.Tracker) Option { return func(f *Fetcher) { f.catalog.Progress = t } }

// WithRetries sets how many times each HTTP request is attempted before
// giving up. Values <= 0 fall back to the xhttp default.
func WithRetries(n int) Option {
	return func(f *Fetcher) {
		if n > 0 {
			f.catalog.Retry.Attempts = n
		}
	}
}

// Fetcher downloads the EPSS catalog (gzip CSV) and writes the decompressed
// CSV to the cache directory so downstream stages can use encoding/csv directly.
type Fetcher struct {
	catalog fetcher.Catalog
}

// New constructs a Fetcher with optional overrides.
func New(opts ...Option) *Fetcher {
	f := &Fetcher{catalog: fetcher.Catalog{
		Source:    sourceName,
		URL:       defaultCatalogURL,
		Filename:  catalogFilename,
		Client:    http.DefaultClient,
		WriteBody: writeDecompressed,
	}}
	for _, opt := range opts {
		opt(f)
	}
	return f
}

// Name reports the source identifier.
func (f *Fetcher) Name() string { return f.catalog.Name() }

// Fetch downloads the EPSS gzip catalog, decompresses it, and writes the
// resulting CSV under <cache-dir>/sources/epss/. Returns the directory root.
func (f *Fetcher) Fetch(ctx context.Context) (string, error) { return f.catalog.Fetch(ctx) }

func writeDecompressed(dest string, resp *http.Response, bar *progress.Bar) (err error) {
	body := bar.ProxyReader(resp.Body)
	defer body.Close()

	gz, err := gzip.NewReader(body)
	if err != nil {
		return fmt.Errorf("gzip reader: %w", err)
	}
	defer gz.Close()

	// Write to a temp file in the same directory and rename atomically only on
	// success, so a failed download (gzip error, bomb-guard, partial copy)
	// never leaves a truncated CSV at dest.
	tmp, err := os.CreateTemp(filepath.Dir(dest), filepath.Base(dest)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		if err != nil {
			_ = os.Remove(tmpName)
		}
	}()

	limited := io.LimitReader(gz, maxDecompressedBytes+1)
	n, err := io.Copy(tmp, limited)
	if err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write %s: %w", tmpName, err)
	}
	if n > maxDecompressedBytes {
		_ = tmp.Close()
		return fmt.Errorf("decompressed payload exceeds %d bytes", maxDecompressedBytes)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tmpName, err)
	}
	if err = os.Rename(tmpName, dest); err != nil {
		return fmt.Errorf("rename %s -> %s: %w", tmpName, dest, err)
	}
	return nil
}
