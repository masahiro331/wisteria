package fetcher

import (
	"context"
	"fmt"
	"net/http"
	"path/filepath"

	"github.com/masahiro331/wisteria/internal/fetcher/progress"
	"github.com/masahiro331/wisteria/internal/x/cachedir"
	xhttp "github.com/masahiro331/wisteria/internal/x/http"
)

// Catalog is the shared engine behind the single-file catalog fetchers
// (kev, epss, exploitdb): GET one URL, persist it as one file under
// <cache-dir>/sources/<Source>/, return the directory. The per-source
// packages own their defaults and functional options and delegate
// Name/Fetch here, so the download flow (retry, status check, progress,
// destination layout) is written once.
type Catalog struct {
	// Source is the cachedir subdirectory, the progress-bar label, and
	// the Fetcher.Name() value.
	Source string
	// URL is the upstream catalog location.
	URL string
	// Filename is the on-disk name under the source cache directory.
	Filename string

	Client   *http.Client
	CacheDir string
	Progress *progress.Tracker
	Retry    xhttp.RetryOptions

	// WriteBody persists the HTTP response into dest. nil means "save
	// the payload as-is" (WriteResponse). Sources that transform the
	// stream (e.g. epss decompresses gzip) plug in their own writer.
	WriteBody func(dest string, resp *http.Response, bar *progress.Bar) error
}

// Name reports the source identifier.
func (c *Catalog) Name() string { return c.Source }

// Fetch downloads the catalog into the cache directory and returns the
// directory root.
func (c *Catalog) Fetch(ctx context.Context) (string, error) {
	dir, err := cachedir.Dir(c.CacheDir, c.Source)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.URL, http.NoBody)
	if err != nil {
		return "", err
	}
	resp, err := xhttp.DoWithRetry(ctx, c.Client, req, c.Retry)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET %s: status %d", c.URL, resp.StatusCode)
	}

	write := c.WriteBody
	if write == nil {
		write = WriteResponse
	}
	dest := filepath.Join(dir, c.Filename)
	if err := write(dest, resp, c.Progress.Bar(c.Source, resp.ContentLength)); err != nil {
		return "", err
	}
	c.Progress.Wait()
	return dir, nil
}
