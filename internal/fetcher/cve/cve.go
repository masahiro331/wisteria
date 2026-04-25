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

// Fetcher downloads the MITRE CVEListV5 tarball.
type Fetcher struct {
	archiveURL string
	client     *http.Client
	cacheDir   string
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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.archiveURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET %s: status %d", f.archiveURL, resp.StatusCode)
	}

	dest := filepath.Join(dir, path.Base(f.archiveURL))
	out, err := os.Create(dest)
	if err != nil {
		return "", err
	}
	defer out.Close()
	if _, err := io.Copy(out, resp.Body); err != nil {
		return "", fmt.Errorf("write %s: %w", dest, err)
	}
	return dir, nil
}
