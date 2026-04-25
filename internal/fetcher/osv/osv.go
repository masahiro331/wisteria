// Package osv fetches vulnerability data from the OSV.dev distribution.
package osv

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/masahiro331/wisteria/internal/cache"
)

const (
	sourceName     = "osv"
	defaultBaseURL = "https://osv-vulnerabilities.storage.googleapis.com"
	ecosystemsPath = "ecosystems.txt"
	archiveName    = "all.zip"
)

// Option configures a Fetcher.
type Option func(*Fetcher)

// WithBaseURL overrides the OSV distribution base URL. Useful for tests.
func WithBaseURL(u string) Option { return func(f *Fetcher) { f.baseURL = u } }

// WithHTTPClient injects a custom HTTP client.
func WithHTTPClient(c *http.Client) Option { return func(f *Fetcher) { f.client = c } }

// WithCacheDir overrides the cache root used to store downloads.
func WithCacheDir(dir string) Option { return func(f *Fetcher) { f.cacheDir = dir } }

// Fetcher downloads OSV per-ecosystem archives.
type Fetcher struct {
	baseURL  string
	client   *http.Client
	cacheDir string
}

// New constructs a Fetcher with optional overrides.
func New(opts ...Option) *Fetcher {
	f := &Fetcher{baseURL: defaultBaseURL, client: http.DefaultClient}
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
	dir, err := cache.Dir(f.cacheDir, sourceName)
	if err != nil {
		return "", err
	}

	ecosystems, err := f.listEcosystems(ctx)
	if err != nil {
		return "", fmt.Errorf("list ecosystems: %w", err)
	}

	for _, eco := range ecosystems {
		if err := f.downloadEcosystem(ctx, dir, eco); err != nil {
			return "", fmt.Errorf("download %s: %w", eco, err)
		}
	}
	return dir, nil
}

func (f *Fetcher) listEcosystems(ctx context.Context) ([]string, error) {
	body, err := f.get(ctx, ecosystemsPath)
	if err != nil {
		return nil, err
	}
	defer body.Close()

	var out []string
	scanner := bufio.NewScanner(body)
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
	body, err := f.get(ctx, ecosystem+"/"+archiveName)
	if err != nil {
		return err
	}
	defer body.Close()

	dir := filepath.Join(root, ecosystem)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	dest := filepath.Join(dir, archiveName)
	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, body); err != nil {
		return fmt.Errorf("write %s: %w", dest, err)
	}
	return nil
}

func (f *Fetcher) get(ctx context.Context, path string) (io.ReadCloser, error) {
	u, err := url.JoinPath(f.baseURL, path)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("GET %s: status %d", u, resp.StatusCode)
	}
	return resp.Body, nil
}
