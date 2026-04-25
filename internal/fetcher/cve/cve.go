// Package cve fetches the MITRE CVEListV5 archive.
package cve

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"

	"github.com/masahiro331/wisteria/internal/cache"
	"github.com/masahiro331/wisteria/internal/extract"
	"github.com/masahiro331/wisteria/internal/httpx"
	"github.com/masahiro331/wisteria/internal/progress"
)

const (
	sourceName        = "cve"
	defaultArchiveURL = "https://github.com/CVEProject/cvelistV5/archive/refs/heads/main.tar.gz"
)

// Option configures a Fetcher.
type Option func(*Fetcher)

// WithArchiveURL overrides the upstream archive URL.
func WithArchiveURL(u string) Option { return func(f *Fetcher) { f.archiveURL = u } }

// WithHTTPClient injects a custom HTTP client.
func WithHTTPClient(c *http.Client) Option { return func(f *Fetcher) { f.client = c } }

// WithCacheDir overrides the cache root used to store downloads.
func WithCacheDir(dir string) Option { return func(f *Fetcher) { f.cacheDir = dir } }

// WithProgress attaches a progress tracker. A nil tracker disables progress UI.
func WithProgress(t *progress.Tracker) Option { return func(f *Fetcher) { f.progress = t } }

// WithRetries sets how many times each HTTP request is attempted before
// giving up. Values <= 0 fall back to the httpx default.
func WithRetries(n int) Option {
	return func(f *Fetcher) {
		if n > 0 {
			f.retry.Attempts = n
		}
	}
}

// Fetcher downloads the MITRE CVEListV5 tarball.
type Fetcher struct {
	archiveURL string
	client     *http.Client
	cacheDir   string
	progress   *progress.Tracker
	retry      httpx.RetryOptions
}

// New constructs a Fetcher with optional overrides.
func New(opts ...Option) *Fetcher {
	f := &Fetcher{archiveURL: defaultArchiveURL, client: http.DefaultClient}
	for _, opt := range opts {
		opt(f)
	}
	return f
}

// Name reports the source identifier.
func (f *Fetcher) Name() string { return sourceName }

// Fetch downloads the archive into the cache directory and returns the
// directory root.
func (f *Fetcher) Fetch(ctx context.Context) (string, error) {
	dir, err := cache.Dir(f.cacheDir, sourceName)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.archiveURL, http.NoBody)
	if err != nil {
		return "", err
	}
	resp, err := httpx.DoWithRetry(ctx, f.client, req, f.retry)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET %s: status %d", f.archiveURL, resp.StatusCode)
	}

	dest := filepath.Join(dir, path.Base(f.archiveURL))
	if err := writeArchive(dest, resp, f.progress.Bar(sourceName, resp.ContentLength)); err != nil {
		return "", err
	}
	f.progress.Wait()

	if err := extract.TarGz(dest, dir); err != nil {
		return "", fmt.Errorf("extract %s: %w", dest, err)
	}
	if err := os.Remove(dest); err != nil {
		return "", fmt.Errorf("remove archive %s: %w", dest, err)
	}
	return dir, nil
}

func writeArchive(dest string, resp *http.Response, bar *progress.Bar) error {
	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	body := bar.ProxyReader(resp.Body)
	if _, err := io.Copy(out, body); err != nil {
		_ = body.Close()
		_ = out.Close()
		return fmt.Errorf("write %s: %w", dest, err)
	}
	if err := body.Close(); err != nil {
		_ = out.Close()
		return fmt.Errorf("close body: %w", err)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("close %s: %w", dest, err)
	}
	return nil
}
