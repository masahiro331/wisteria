package cve

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
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

func TestFetcher_Fetch_ExtractsAndRemovesArchive(t *testing.T) {
	payload := tarGzBytes(t, map[string]string{
		"cvelistV5-main/README.md":            "hi",
		"cvelistV5-main/cves/CVE-2024-1.json": `{"id":"CVE-2024-1"}`,
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(payload)
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

	want := map[string]string{
		filepath.Join(dir, "cvelistV5-main", "README.md"):               "hi",
		filepath.Join(dir, "cvelistV5-main", "cves", "CVE-2024-1.json"): `{"id":"CVE-2024-1"}`,
	}
	for path, body := range want {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if string(got) != body {
			t.Errorf("%s = %q, want %q", path, got, body)
		}
	}

	archive := filepath.Join(dir, "main.tar.gz")
	if _, err := os.Stat(archive); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("expected %s to be removed, stat err = %v", archive, err)
	}
}

func TestFetcher_Fetch_RespectsCacheDirOverride(t *testing.T) {
	payload := tarGzBytes(t, map[string]string{
		"cvelistV5-main/x.json": "{}",
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(payload)
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
	want := filepath.Join(override, "sources", "cve")
	if dir != want {
		t.Errorf("dir = %q, want %q", dir, want)
	}
	if _, err := os.Stat(filepath.Join(dir, "cvelistV5-main", "x.json")); err != nil {
		t.Errorf("expected extracted file: %v", err)
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

func tarGzBytes(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range entries {
		hdr := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(body))}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("WriteHeader %s: %v", name, err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatalf("Write %s: %v", name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	return buf.Bytes()
}
