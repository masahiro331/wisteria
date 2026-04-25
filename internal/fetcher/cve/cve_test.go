package cve

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFetcher_Name(t *testing.T) {
	if got := New().Name(); got != "cve" {
		t.Errorf("Name() = %q, want %q", got, "cve")
	}
}

func TestFetcher_Fetch_DownloadsArchive(t *testing.T) {
	const payload = "tarball-bytes"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(payload))
	}))
	defer srv.Close()

	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("XDG_CACHE_HOME", tmp)

	f := New(WithArchiveURL(srv.URL+"/main.tar.gz"), WithHTTPClient(srv.Client()))
	dir, err := f.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch returned error: %v", err)
	}

	if !strings.Contains(dir, "cve") {
		t.Errorf("expected dir to contain %q, got %q", "cve", dir)
	}
	got, err := os.ReadFile(filepath.Join(dir, "main.tar.gz"))
	if err != nil {
		t.Fatalf("read archive: %v", err)
	}
	if string(got) != payload {
		t.Errorf("archive contents = %q, want %q", got, payload)
	}
}

func TestFetcher_Fetch_RespectsCacheDirOverride(t *testing.T) {
	const payload = "tarball-bytes"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(payload))
	}))
	defer srv.Close()

	override := t.TempDir()
	f := New(
		WithArchiveURL(srv.URL+"/main.tar.gz"),
		WithHTTPClient(srv.Client()),
		WithCacheDir(override),
	)
	dir, err := f.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch returned error: %v", err)
	}
	want := filepath.Join(override, "cve")
	if dir != want {
		t.Errorf("dir = %q, want %q", dir, want)
	}
	if _, err := os.Stat(filepath.Join(dir, "main.tar.gz")); err != nil {
		t.Errorf("expected archive under override: %v", err)
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

	f := New(WithArchiveURL(srv.URL+"/main.tar.gz"), WithHTTPClient(srv.Client()))
	if _, err := f.Fetch(context.Background()); err == nil {
		t.Fatal("expected error, got nil")
	}
}
