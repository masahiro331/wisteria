// Package kev fetches the CISA Known Exploited Vulnerabilities catalog.
package kev

import (
	"context"
	"fmt"
	"net/http"
	"path/filepath"

	"github.com/masahiro331/wisteria/internal/fetcher"
	"github.com/masahiro331/wisteria/internal/fetcher/progress"
	"github.com/masahiro331/wisteria/internal/x/cachedir"
	xhttp "github.com/masahiro331/wisteria/internal/x/http"
)

const (
	sourceName        = "kev"
	defaultCatalogURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	catalogFilename   = "known_exploited_vulnerabilities.json"
)

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

// Fetcher downloads the CISA KEV catalog as a single JSON file.
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

// Fetch downloads the KEV catalog into the cache directory and returns the
// directory root.
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
	if err := fetcher.WriteResponse(dest, resp, f.progress.Bar(sourceName, resp.ContentLength)); err != nil {
		return "", err
	}
	f.progress.Wait()
	return dir, nil
}
