// Package epss fetches the FIRST EPSS daily score catalog.
package epss

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/masahiro331/wisteria/internal/fetcher/progress"
	"github.com/masahiro331/wisteria/internal/x/cachedir"
	xhttp "github.com/masahiro331/wisteria/internal/x/http"
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
func WithCatalogURL(u string) Option { return func(f *Fetcher) { f.catalogURL = u } }

// WithHTTPClient injects a custom HTTP client.
func WithHTTPClient(c *http.Client) Option { return func(f *Fetcher) { f.client = c } }

// WithCacheDir overrides the cache root used to store downloads.
func WithCacheDir(dir string) Option { return func(f *Fetcher) { f.cacheDir = dir } }

// WithProgress attaches a progress tracker. A nil tracker disables progress UI.
func WithProgress(t *progress.Tracker) Option { return func(f *Fetcher) { f.progress = t } }

// WithRetries sets how many times each HTTP request is attempted before
// giving up. Values <= 0 fall back to the xhttp default.
func WithRetries(n int) Option {
	return func(f *Fetcher) {
		if n > 0 {
			f.retry.Attempts = n
		}
	}
}

// Fetcher downloads the EPSS catalog (gzip CSV) and writes the decompressed
// CSV to the cache directory so downstream stages can use encoding/csv directly.
type Fetcher struct {
	catalogURL string
	client     *http.Client
	cacheDir   string
	progress   *progress.Tracker
	retry      xhttp.RetryOptions
}

// New constructs a Fetcher with optional overrides.
func New(opts ...Option) *Fetcher {
	f := &Fetcher{catalogURL: defaultCatalogURL, client: http.DefaultClient}
	for _, opt := range opts {
		opt(f)
	}
	return f
}

// Name reports the source identifier.
func (f *Fetcher) Name() string { return sourceName }

// Fetch downloads the EPSS gzip catalog, decompresses it, and writes the
// resulting CSV under <cache-dir>/sources/epss/. Returns the directory root.
func (f *Fetcher) Fetch(ctx context.Context) (string, error) {
	dir, err := cachedir.Dir(f.cacheDir, sourceName)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.catalogURL, http.NoBody)
	if err != nil {
		return "", err
	}
	resp, err := xhttp.DoWithRetry(ctx, f.client, req, f.retry)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET %s: status %d", f.catalogURL, resp.StatusCode)
	}

	dest := filepath.Join(dir, catalogFilename)
	if err := writeDecompressed(dest, resp, f.progress.Bar(sourceName, resp.ContentLength)); err != nil {
		return "", err
	}
	f.progress.Wait()
	return dir, nil
}

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
