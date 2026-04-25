package epss

import (
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestFetcher_Name(t *testing.T) {
	if got := New().Name(); got != "epss" {
		t.Errorf("Name() = %q, want %q", got, "epss")
	}
}

func TestFetcher_Fetch_DecompressesAndSavesPlainCSV(t *testing.T) {
	const csv = "#model_version:v2025.03.14,score_date:2026-04-24T12:55:00Z\ncve,epss,percentile\nCVE-2024-0001,0.5,0.9\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(gzipBytes(t, csv))
	}))
	defer srv.Close()

	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("XDG_CACHE_HOME", tmp)

	f := New(WithCatalogURL(srv.URL+"/epss_scores-current.csv.gz"), WithHTTPClient(srv.Client()))
	dir, err := f.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch returned error: %v", err)
	}

	plain := filepath.Join(dir, "epss_scores-current.csv")
	got, err := os.ReadFile(plain)
	if err != nil {
		t.Fatalf("read plain CSV: %v", err)
	}
	if string(got) != csv {
		t.Errorf("CSV body mismatch:\n got: %q\nwant: %q", got, csv)
	}

	gz := filepath.Join(dir, "epss_scores-current.csv.gz")
	if _, err := os.Stat(gz); !os.IsNotExist(err) {
		t.Errorf("expected .csv.gz to be absent, stat err = %v", err)
	}
}

func TestFetcher_Fetch_RespectsCacheDirOverride(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(gzipBytes(t, "cve,epss,percentile\n"))
	}))
	defer srv.Close()

	override := t.TempDir()
	f := New(
		WithCatalogURL(srv.URL+"/x.csv.gz"),
		WithHTTPClient(srv.Client()),
		WithCacheDir(override),
	)
	dir, err := f.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch returned error: %v", err)
	}
	want := filepath.Join(override, "sources", "epss")
	if dir != want {
		t.Errorf("dir = %q, want %q", dir, want)
	}
	if _, err := os.Stat(filepath.Join(dir, "epss_scores-current.csv")); err != nil {
		t.Errorf("expected plain CSV file: %v", err)
	}
}

func TestFetcher_Fetch_ReturnsErrorOnNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusBadGateway)
	}))
	defer srv.Close()

	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("XDG_CACHE_HOME", tmp)

	f := New(WithCatalogURL(srv.URL+"/x.csv.gz"), WithHTTPClient(srv.Client()))
	if _, err := f.Fetch(context.Background()); err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestFetcher_Fetch_RejectsOversizedPayload(t *testing.T) {
	// Serve a tiny gzip whose decompressed payload exceeds the small cap we
	// inject below. This proves the LimitReader-based bomb guard fires before
	// writing an unbounded amount to disk.
	body := bytes.Repeat([]byte("x"), 4096)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(gzipBytes(t, string(body)))
	}))
	defer srv.Close()

	prev := maxDecompressedBytes
	maxDecompressedBytes = 1024
	t.Cleanup(func() { maxDecompressedBytes = prev })

	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("XDG_CACHE_HOME", tmp)

	f := New(WithCatalogURL(srv.URL+"/x.csv.gz"), WithHTTPClient(srv.Client()))
	if _, err := f.Fetch(context.Background()); err == nil {
		t.Fatal("expected error for oversized payload, got nil")
	}
}

func TestFetcher_Fetch_ReturnsErrorOnNonGzipBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not a gzip stream"))
	}))
	defer srv.Close()

	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("XDG_CACHE_HOME", tmp)

	f := New(WithCatalogURL(srv.URL+"/x.csv.gz"), WithHTTPClient(srv.Client()))
	if _, err := f.Fetch(context.Background()); err == nil {
		t.Fatal("expected error for non-gzip body, got nil")
	}
}

func gzipBytes(t *testing.T, body string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write([]byte(body)); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}
