// Package vulncheckkev fetches the VulnCheck KEV catalog (VulnCheck Known
// Exploited Vulnerabilities, https://vulncheck.com/kev) through the VulnCheck
// backup API. The API needs a Community token; it answers with a signed
// download URL (valid for 15 minutes) and the backup's sha256. The zip holds
// one JSON file, which is kept as-is under <cache-dir>/sources/vulncheck-kev/.
//
// The previous catalog is removed before anything else, so a missing token or
// a failed fetch never leaves yesterday's catalog for the annotator to attach.
package vulncheckkev

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/masahiro331/wisteria/internal/fetcher"
	"github.com/masahiro331/wisteria/internal/fetcher/progress"
	"github.com/masahiro331/wisteria/internal/unified/vulncheckkev"
	"github.com/masahiro331/wisteria/internal/x/archive"
	"github.com/masahiro331/wisteria/internal/x/cachedir"
	xhttp "github.com/masahiro331/wisteria/internal/x/http"
)

const (
	sourceName    = "vulncheck-kev"
	defaultAPIURL = "https://api.vulncheck.com/v3/backup/vulncheck-kev"
	// TokenEnv is the environment variable the CLI reads the token from.
	TokenEnv = "VULNCHECK_API_TOKEN"
)

// ErrNoToken reports that no VulnCheck API token was given.
var ErrNoToken = fmt.Errorf("%s is not set: %w", TokenEnv, fetcher.ErrNotConfigured)

// Option configures a Fetcher.
type Option func(*Fetcher)

// WithToken sets the VulnCheck API token.
func WithToken(token string) Option { return func(f *Fetcher) { f.token = strings.TrimSpace(token) } }

// WithAPIURL overrides the backup API endpoint.
func WithAPIURL(u string) Option { return func(f *Fetcher) { f.apiURL = u } }

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

// Fetcher downloads the VulnCheck KEV backup.
type Fetcher struct {
	token    string
	apiURL   string
	client   *http.Client
	cacheDir string
	progress *progress.Tracker
	retry    xhttp.RetryOptions
}

// New constructs a Fetcher with optional overrides.
func New(opts ...Option) *Fetcher {
	f := &Fetcher{apiURL: defaultAPIURL, client: http.DefaultClient}
	for _, opt := range opts {
		opt(f)
	}
	return f
}

// Name reports the source identifier.
func (f *Fetcher) Name() string { return sourceName }

// backup is the part of the backup API response this fetcher reads.
type backup struct {
	Data []struct {
		Filename string `json:"filename"`
		SHA256   string `json:"sha256"`
		URL      string `json:"url"`
	} `json:"data"`
}

// Fetch downloads the catalog into the cache directory and returns the
// directory. Without a token it returns ErrNoToken, having removed any
// previous catalog.
func (f *Fetcher) Fetch(ctx context.Context) (string, error) {
	dir, err := cachedir.Dir(f.cacheDir, sourceName)
	if err != nil {
		return "", err
	}
	if err := clearDir(dir); err != nil {
		return "", err
	}
	if f.token == "" {
		return "", ErrNoToken
	}
	b, err := f.backupInfo(ctx)
	if err != nil {
		return "", err
	}
	tmp, err := os.MkdirTemp(dir, ".download-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmp)
	zipPath := filepath.Join(tmp, "backup.zip")
	if err := f.download(ctx, b.Data[0].URL, b.Data[0].SHA256, zipPath); err != nil {
		return "", err
	}
	extracted := filepath.Join(tmp, "x")
	if err := archive.Zip(zipPath, extracted); err != nil {
		return "", err
	}
	src := filepath.Join(extracted, vulncheckkev.CatalogFilename)
	if _, err := os.Stat(src); err != nil {
		return "", fmt.Errorf("vulncheck-kev: backup has no %s: %w", vulncheckkev.CatalogFilename, err)
	}
	if err := os.Rename(src, filepath.Join(dir, vulncheckkev.CatalogFilename)); err != nil {
		return "", err
	}
	return dir, nil
}

// clearDir empties dir, keeping dir itself.
func clearDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
			return err
		}
	}
	return nil
}

func (f *Fetcher) backupInfo(ctx context.Context) (backup, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.apiURL, http.NoBody)
	if err != nil {
		return backup{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+f.token)
	resp, err := xhttp.DoWithRetry(ctx, f.client, req, f.retry)
	if err != nil {
		return backup{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return backup{}, fmt.Errorf("GET %s: status %d", f.apiURL, resp.StatusCode)
	}
	var b backup
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&b); err != nil {
		return backup{}, fmt.Errorf("vulncheck-kev: parse backup response: %w", err)
	}
	if len(b.Data) == 0 || b.Data[0].URL == "" || b.Data[0].SHA256 == "" {
		return backup{}, errors.New("vulncheck-kev: backup response has no download URL or checksum")
	}
	return b, nil
}

// download fetches the backup zip to dest and checks its sha256. The signed
// URL is fetched without the API token: it is a different host.
func (f *Fetcher) download(ctx context.Context, url, wantSum, dest string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return err
	}
	resp, err := xhttp.DoWithRetry(ctx, f.client, req, f.retry)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("vulncheck-kev: download backup: status %d", resp.StatusCode)
	}
	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	h := sha256.New()
	body := f.progress.Bar(sourceName, resp.ContentLength).ProxyReader(resp.Body)
	_, err = io.Copy(io.MultiWriter(out, h), body)
	_ = body.Close()
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	f.progress.Wait()
	if err != nil {
		return fmt.Errorf("vulncheck-kev: write backup: %w", err)
	}
	if got := hex.EncodeToString(h.Sum(nil)); !strings.EqualFold(got, wantSum) {
		return fmt.Errorf("vulncheck-kev: backup sha256 %s, want %s", got, wantSum)
	}
	return nil
}
