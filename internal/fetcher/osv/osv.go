// Package osv fetches vulnerability data from the OSV.dev distribution.
package osv

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sync/errgroup"

	"github.com/masahiro331/wisteria/internal/fetcher"
	"github.com/masahiro331/wisteria/internal/fetcher/progress"
	"github.com/masahiro331/wisteria/internal/x/archive"
	"github.com/masahiro331/wisteria/internal/x/cachedir"
	xhttp "github.com/masahiro331/wisteria/internal/x/http"
)

const (
	sourceName         = "osv"
	defaultBaseURL     = "https://osv-vulnerabilities.storage.googleapis.com"
	ecosystemsPath     = "ecosystems.txt"
	archiveName        = "all.zip"
	defaultConcurrency = 4
)

// Option configures a Fetcher.
type Option func(*Fetcher)

// WithBaseURL overrides the OSV distribution base URL. Useful for tests.
func WithBaseURL(u string) Option { return func(f *Fetcher) { f.baseURL = u } }

// WithHTTPClient injects a custom HTTP client.
func WithHTTPClient(c *http.Client) Option { return func(f *Fetcher) { f.client = c } }

// WithCacheDir overrides the cache root used to store downloads.
func WithCacheDir(dir string) Option { return func(f *Fetcher) { f.cacheDir = dir } }

// WithProgress attaches a progress tracker. A nil tracker disables progress UI.
func WithProgress(t *progress.Tracker) Option { return func(f *Fetcher) { f.progress = t } }

// WithConcurrency caps the number of ecosystems downloaded in parallel.
// Values <= 0 fall back to the default.
func WithConcurrency(n int) Option {
	return func(f *Fetcher) {
		if n > 0 {
			f.concurrency = n
		}
	}
}

// WithRetries sets how many times each HTTP request is attempted before
// giving up. Values <= 0 fall back to the xhttp default.
func WithRetries(n int) Option {
	return func(f *Fetcher) {
		if n > 0 {
			f.retry.Attempts = n
		}
	}
}

// Fetcher downloads OSV per-ecosystem archives.
type Fetcher struct {
	baseURL     string
	client      *http.Client
	cacheDir    string
	progress    *progress.Tracker
	concurrency int
	retry       xhttp.RetryOptions
}

// New constructs a Fetcher with optional overrides.
func New(opts ...Option) *Fetcher {
	f := &Fetcher{
		baseURL:     defaultBaseURL,
		client:      http.DefaultClient,
		concurrency: defaultConcurrency,
	}
	for _, opt := range opts {
		opt(f)
	}
	return f
}

// Name reports the source identifier.
func (f *Fetcher) Name() string { return sourceName }

// Fetch downloads the ecosystem list and each ecosystem's archive into the
// cache directory, returning the directory root.
func (f *Fetcher) Fetch(ctx context.Context) (string, error) {
	dir, err := cachedir.Dir(f.cacheDir, sourceName)
	if err != nil {
		return "", err
	}

	ecosystems, err := f.listEcosystems(ctx)
	if err != nil {
		return "", fmt.Errorf("list ecosystems: %w", err)
	}

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(f.concurrency)
	for _, eco := range ecosystems {
		eco := eco
		g.Go(func() error {
			if err := f.downloadEcosystem(gctx, dir, eco); err != nil {
				return fmt.Errorf("download %s: %w", eco, err)
			}
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return "", err
	}
	f.progress.Wait()
	return dir, nil
}

func (f *Fetcher) listEcosystems(ctx context.Context) ([]string, error) {
	resp, err := f.get(ctx, ecosystemsPath)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var out []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		out = append(out, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (f *Fetcher) downloadEcosystem(ctx context.Context, root, ecosystem string) error {
	resp, err := f.get(ctx, ecosystem+"/"+archiveName)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	local := localEcosystem(ecosystem)
	dir := filepath.Join(root, local)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	dest := filepath.Join(dir, archiveName)
	if err := fetcher.WriteResponse(dest, resp, f.progress.Bar(local, resp.ContentLength)); err != nil {
		return err
	}
	if err := archive.Zip(dest, dir); err != nil {
		return fmt.Errorf("extract %s: %w", dest, err)
	}
	if err := os.Remove(dest); err != nil {
		return fmt.Errorf("remove archive %s: %w", dest, err)
	}
	return nil
}

// localEcosystem maps an upstream ecosystem name (as listed in OSV's
// ecosystems.txt) to the directory name used on disk. Upstream's
// "[EMPTY]" sentinel — used for ecosystem-less generic advisories — is
// renamed to "Generic" so the literal brackets don't leak into
// Provenance.Path, IndexEntry.Source, or the standalone bucket name.
// Other ecosystem names are passed through verbatim; case + spacing
// stay as upstream emits them and walker handles space normalization
// itself when building IndexEntry.Source.
func localEcosystem(upstream string) string {
	if upstream == "[EMPTY]" {
		return "Generic"
	}
	return upstream
}

func (f *Fetcher) get(ctx context.Context, path string) (*http.Response, error) {
	u, err := url.JoinPath(f.baseURL, path)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, http.NoBody)
	if err != nil {
		return nil, err
	}
	resp, err := xhttp.DoWithRetry(ctx, f.client, req, f.retry)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("GET %s: status %d", u, resp.StatusCode)
	}
	return resp, nil
}
