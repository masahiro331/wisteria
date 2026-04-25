package kev

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestFetcher_Name(t *testing.T) {
	if got := New().Name(); got != "kev" {
		t.Errorf("Name() = %q, want %q", got, "kev")
	}
}

func TestFetcher_Fetch_SavesCatalogToCacheDir(t *testing.T) {
	const body = `{"title":"CISA Catalog","catalogVersion":"2026.04.24","count":1,"vulnerabilities":[{"cveID":"CVE-2024-0001"}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("XDG_CACHE_HOME", tmp)

	f := New(WithCatalogURL(srv.URL+"/known_exploited_vulnerabilities.json"), WithHTTPClient(srv.Client()))
	dir, err := f.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch returned error: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(dir, "known_exploited_vulnerabilities.json"))
	if err != nil {
		t.Fatalf("read catalog: %v", err)
	}
	if string(got) != body {
		t.Errorf("catalog body mismatch:\n got: %q\nwant: %q", got, body)
	}
}

func TestFetcher_Fetch_RespectsCacheDirOverride(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"vulnerabilities":[]}`))
	}))
	defer srv.Close()

	override := t.TempDir()
	f := New(
		WithCatalogURL(srv.URL+"/known_exploited_vulnerabilities.json"),
		WithHTTPClient(srv.Client()),
		WithCacheDir(override),
	)
	dir, err := f.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch returned error: %v", err)
	}
	want := filepath.Join(override, "sources", "kev")
	if dir != want {
		t.Errorf("dir = %q, want %q", dir, want)
	}
	if _, err := os.Stat(filepath.Join(dir, "known_exploited_vulnerabilities.json")); err != nil {
		t.Errorf("expected catalog file: %v", err)
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

	f := New(WithCatalogURL(srv.URL+"/x.json"), WithHTTPClient(srv.Client()))
	if _, err := f.Fetch(context.Background()); err == nil {
		t.Fatal("expected error, got nil")
	}
}
