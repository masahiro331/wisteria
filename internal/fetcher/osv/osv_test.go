package osv

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
	if got := New().Name(); got != "osv" {
		t.Errorf("Name() = %q, want %q", got, "osv")
	}
}

func TestFetcher_Fetch_DownloadsEcosystemArchives(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/ecosystems.txt", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("PyPI\nGo\n"))
	})
	mux.HandleFunc("/PyPI/all.zip", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("pypi-zip-bytes"))
	})
	mux.HandleFunc("/Go/all.zip", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("go-zip-bytes"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("XDG_CACHE_HOME", tmp)

	f := New(WithBaseURL(srv.URL), WithHTTPClient(srv.Client()))
	dir, err := f.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch returned error: %v", err)
	}

	if !strings.Contains(dir, "osv") {
		t.Errorf("expected dir to contain %q, got %q", "osv", dir)
	}

	cases := map[string]string{
		filepath.Join(dir, "PyPI", "all.zip"): "pypi-zip-bytes",
		filepath.Join(dir, "Go", "all.zip"):   "go-zip-bytes",
	}
	for path, want := range cases {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if string(got) != want {
			t.Errorf("%s contents = %q, want %q", path, got, want)
		}
	}
}

func TestFetcher_Fetch_ReturnsErrorWhenEcosystemListFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("XDG_CACHE_HOME", tmp)

	f := New(WithBaseURL(srv.URL), WithHTTPClient(srv.Client()))
	if _, err := f.Fetch(context.Background()); err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestFetcher_Fetch_RespectsCacheDirOverride(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/ecosystems.txt", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("PyPI\n"))
	})
	mux.HandleFunc("/PyPI/all.zip", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("pypi-zip-bytes"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	override := t.TempDir()
	f := New(
		WithBaseURL(srv.URL),
		WithHTTPClient(srv.Client()),
		WithCacheDir(override),
	)
	dir, err := f.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch returned error: %v", err)
	}

	want := filepath.Join(override, "osv")
	if dir != want {
		t.Errorf("dir = %q, want %q", dir, want)
	}
	if _, err := os.Stat(filepath.Join(dir, "PyPI", "all.zip")); err != nil {
		t.Errorf("expected archive under override: %v", err)
	}
}
