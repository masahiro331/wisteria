package vulncheckkev

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/masahiro331/wisteria/internal/fetcher"
	"github.com/masahiro331/wisteria/internal/unified/vulncheckkev"
)

const catalogBody = `[{"cve":["CVE-2024-4577"],"date_added":"2024-06-07T00:00:00Z"}]`

func zipWith(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// backupServer serves the backup API at /v3/backup/vulncheck-kev and the zip
// at /download. sum overrides the advertised sha256 when non-empty.
type backupServer struct {
	*httptest.Server
	zip           []byte
	sum           string
	apiStatus     int
	apiAuth       string // Authorization the API call carried
	downloadAuth  string // Authorization the download carried
	downloadCalls int
	apiCalls      int
	failDownloads int    // answer this many downloads with 403
	dropDownloads bool   // close download connections without a response
	downloadQuery string // query appended to the advertised download URL
}

func newBackupServer(t *testing.T, zipBody []byte) *backupServer {
	t.Helper()
	s := &backupServer{zip: zipBody, apiStatus: http.StatusOK}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v3/backup/vulncheck-kev":
			s.apiCalls++
			s.apiAuth = r.Header.Get("Authorization")
			if s.apiStatus != http.StatusOK {
				w.WriteHeader(s.apiStatus)
				return
			}
			sum := s.sum
			if sum == "" {
				h := sha256.Sum256(s.zip)
				sum = hex.EncodeToString(h[:])
			}
			fmt.Fprintf(w, `{"_meta":{"index":"vulncheck-kev"},"data":[{"filename":"vulncheck-kev-1.zip","sha256":%q,"date_added":"2026-11-13T05:57:12Z","url":%q}]}`,
				sum, s.URL+"/download?"+s.downloadQuery)
		case "/download":
			s.downloadCalls++
			s.downloadAuth = r.Header.Get("Authorization")
			if s.dropDownloads {
				hj, _ := w.(http.Hijacker)
				conn, _, _ := hj.Hijack()
				_ = conn.Close()
				return
			}
			if s.failDownloads > 0 {
				s.failDownloads--
				w.WriteHeader(http.StatusForbidden)
				return
			}
			_, _ = w.Write(s.zip)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(s.Close)
	return s
}

func newFetcher(s *backupServer, cacheDir, token string) *Fetcher {
	return New(WithAPIURL(s.URL+"/v3/backup/vulncheck-kev"), WithHTTPClient(s.Client()),
		WithCacheDir(cacheDir), WithToken(token))
}

func catalogPath(cacheDir string) string {
	return filepath.Join(cacheDir, "sources", "vulncheck-kev", vulncheckkev.CatalogFilename)
}

func TestFetcher_Name(t *testing.T) {
	if got := New().Name(); got != "vulncheck-kev" {
		t.Errorf("Name() = %q", got)
	}
}

func TestFetch_DownloadsAndExtractsCatalog(t *testing.T) {
	s := newBackupServer(t, zipWith(t, map[string]string{vulncheckkev.CatalogFilename: catalogBody}))
	cache := t.TempDir()
	dir, err := newFetcher(s, cache, "test-token").Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Dir(catalogPath(cache)); dir != want {
		t.Errorf("dir = %s, want %s", dir, want)
	}
	if s.apiAuth != "Bearer test-token" {
		t.Errorf("API Authorization = %q", s.apiAuth)
	}
	got, err := os.ReadFile(catalogPath(cache))
	if err != nil || string(got) != catalogBody {
		t.Fatalf("catalog = %q, %v", got, err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("source dir holds %d entries, want only the catalog", len(entries))
	}
}

func TestFetch_TokenNotSentToDownloadURL(t *testing.T) {
	s := newBackupServer(t, zipWith(t, map[string]string{vulncheckkev.CatalogFilename: catalogBody}))
	if _, err := newFetcher(s, t.TempDir(), "test-token").Fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s.downloadCalls != 1 || s.downloadAuth != "" {
		t.Errorf("download calls = %d, Authorization = %q; want 1 call without the token", s.downloadCalls, s.downloadAuth)
	}
}

func TestFetch_SHA256Mismatch(t *testing.T) {
	s := newBackupServer(t, zipWith(t, map[string]string{vulncheckkev.CatalogFilename: catalogBody}))
	s.sum = "00"
	cache := t.TempDir()
	if _, err := newFetcher(s, cache, "test-token").Fetch(context.Background()); err == nil {
		t.Fatal("want a checksum error")
	}
	if _, err := os.Stat(catalogPath(cache)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("catalog left behind: %v", err)
	}
}

func TestFetch_ZipWithoutCatalog(t *testing.T) {
	s := newBackupServer(t, zipWith(t, map[string]string{"other.json": "[]"}))
	if _, err := newFetcher(s, t.TempDir(), "test-token").Fetch(context.Background()); err == nil {
		t.Fatal("want an error for a zip without the catalog")
	}
}

func writeStale(t *testing.T, cache string) {
	t.Helper()
	p := catalogPath(cache)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("[]"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestFetch_NoTokenRemovesStaleCatalog(t *testing.T) {
	s := newBackupServer(t, nil)
	cache := t.TempDir()
	writeStale(t, cache)
	_, err := newFetcher(s, cache, "").Fetch(context.Background())
	if !errors.Is(err, ErrNoToken) || !errors.Is(err, fetcher.ErrNotConfigured) {
		t.Errorf("err = %v, want ErrNoToken (fetcher.ErrNotConfigured)", err)
	}
	if s.apiAuth != "" {
		t.Error("the API must not be called without a token")
	}
	if _, err := os.Stat(catalogPath(cache)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("stale catalog left behind: %v", err)
	}
}

func TestFetch_AuthErrorRemovesStaleCatalog(t *testing.T) {
	s := newBackupServer(t, nil)
	s.apiStatus = http.StatusUnauthorized
	cache := t.TempDir()
	writeStale(t, cache)
	if _, err := newFetcher(s, cache, "bad").Fetch(context.Background()); err == nil {
		t.Fatal("want an error on 401")
	}
	if _, err := os.Stat(catalogPath(cache)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("stale catalog left behind: %v", err)
	}
}

// A catalog that downloads but does not parse is a fetch error, so `fetch
// all` warns and unify never sees it.
func TestFetch_UnparsableCatalogIsAnError(t *testing.T) {
	s := newBackupServer(t, zipWith(t, map[string]string{vulncheckkev.CatalogFilename: `{"not":"an array"}`}))
	cache := t.TempDir()
	if _, err := newFetcher(s, cache, "test-token").Fetch(context.Background()); err == nil {
		t.Fatal("want a parse error")
	}
	if _, err := os.Stat(catalogPath(cache)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("catalog placed: %v", err)
	}
}

func TestFetch_ZipSlipIsRejected(t *testing.T) {
	s := newBackupServer(t, zipWith(t, map[string]string{"../evil.json": "[]", vulncheckkev.CatalogFilename: catalogBody}))
	cache := t.TempDir()
	if _, err := newFetcher(s, cache, "test-token").Fetch(context.Background()); err == nil {
		t.Fatal("want an error for a zip-slip entry")
	}
	if _, err := os.Stat(catalogPath(cache)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("catalog placed: %v", err)
	}
	matches, _ := filepath.Glob(filepath.Join(cache, "sources", "*.json"))
	if len(matches) != 0 {
		t.Errorf("file written outside the source dir: %v", matches)
	}
}

// A failed download asks the API for a fresh signed URL once more.
func TestFetch_RetriesWithAFreshURL(t *testing.T) {
	s := newBackupServer(t, zipWith(t, map[string]string{vulncheckkev.CatalogFilename: catalogBody}))
	s.failDownloads = 1
	cache := t.TempDir()
	if _, err := newFetcher(s, cache, "test-token").Fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s.apiCalls != 2 || s.downloadCalls != 2 {
		t.Errorf("api calls = %d, download calls = %d; want 2 and 2", s.apiCalls, s.downloadCalls)
	}
}

// A download error names the host only: the signed URL's query is a
// credential for 15 minutes and must not reach the logs.
func TestFetch_DownloadErrorHidesTheSignedQuery(t *testing.T) {
	s := newBackupServer(t, nil)
	s.downloadQuery = "X-Amz-Signature=secret-signature"
	s.dropDownloads = true
	_, err := newFetcher(s, t.TempDir(), "test-token").Fetch(context.Background())
	if err == nil {
		t.Fatal("want a download error")
	}
	if strings.Contains(err.Error(), "secret-signature") || strings.Contains(err.Error(), "X-Amz") {
		t.Errorf("error leaks the signed URL: %v", err)
	}
}
