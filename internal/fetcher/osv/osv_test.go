package osv

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestFetcher_Name(t *testing.T) {
	if got := New().Name(); got != "osv" {
		t.Errorf("Name() = %q, want %q", got, "osv")
	}
}

func TestFetcher_Fetch_ExtractsAndRemovesArchives(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/ecosystems.txt", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("PyPI\nGo\n"))
	})
	mux.HandleFunc("/PyPI/all.zip", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(zipBytes(t, map[string]string{"CVE-2024-1.json": `{"id":"PyPI-1"}`}))
	})
	mux.HandleFunc("/Go/all.zip", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(zipBytes(t, map[string]string{"CVE-2024-2.json": `{"id":"GO-1"}`}))
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

	want := map[string]string{
		filepath.Join(dir, "PyPI", "CVE-2024-1.json"): `{"id":"PyPI-1"}`,
		filepath.Join(dir, "Go", "CVE-2024-2.json"):   `{"id":"GO-1"}`,
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

	// Archives must be removed after extraction.
	for _, eco := range []string{"PyPI", "Go"} {
		archive := filepath.Join(dir, eco, "all.zip")
		if _, err := os.Stat(archive); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("expected %s to be removed, stat err = %v", archive, err)
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

func TestFetcher_Fetch_LimitsConcurrency(t *testing.T) {
	const (
		ecoCount = 8
		limit    = 3
	)
	var ecosystems []string
	for i := 0; i < ecoCount; i++ {
		ecosystems = append(ecosystems, fmt.Sprintf("eco%d", i))
	}

	var (
		inFlight int64
		peak     int64
	)
	mux := http.NewServeMux()
	mux.HandleFunc("/ecosystems.txt", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Join(ecosystems, "\n")))
	})
	for _, eco := range ecosystems {
		mux.HandleFunc("/"+eco+"/all.zip", func(w http.ResponseWriter, _ *http.Request) {
			cur := atomic.AddInt64(&inFlight, 1)
			defer atomic.AddInt64(&inFlight, -1)
			for {
				old := atomic.LoadInt64(&peak)
				if cur <= old || atomic.CompareAndSwapInt64(&peak, old, cur) {
					break
				}
			}
			time.Sleep(50 * time.Millisecond)
			_, _ = w.Write(zipBytes(t, map[string]string{"v.json": "{}"}))
		})
	}
	srv := httptest.NewServer(mux)
	defer srv.Close()

	override := t.TempDir()
	f := New(
		WithBaseURL(srv.URL),
		WithHTTPClient(srv.Client()),
		WithCacheDir(override),
		WithConcurrency(limit),
	)
	if _, err := f.Fetch(context.Background()); err != nil {
		t.Fatalf("Fetch returned error: %v", err)
	}

	got := atomic.LoadInt64(&peak)
	if got != int64(limit) {
		t.Errorf("peak in-flight = %d, want exactly %d", got, limit)
	}
}

// TestFetcher_Fetch_CancelsSiblingsOnError verifies that when one
// ecosystem download fails, Fetch returns promptly rather than waiting
// for the other (slow) downloads to finish. We don't assert on the
// server-side ctx cancellation because that races with the
// client-server handshake; the elapsed-time check is what matters.
func TestFetcher_Fetch_CancelsSiblingsOnError(t *testing.T) {
	ecosystems := []string{"fail", "slow1", "slow2", "slow3"}
	const slowDelay = 5 * time.Second

	mux := http.NewServeMux()
	mux.HandleFunc("/ecosystems.txt", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Join(ecosystems, "\n")))
	})
	mux.HandleFunc("/fail/all.zip", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	for _, eco := range ecosystems[1:] {
		mux.HandleFunc("/"+eco+"/all.zip", func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-r.Context().Done():
			case <-time.After(slowDelay):
				_, _ = w.Write(zipBytes(t, map[string]string{"v.json": "{}"}))
			}
		})
	}
	srv := httptest.NewServer(mux)
	defer srv.Close()

	override := t.TempDir()
	f := New(
		WithBaseURL(srv.URL),
		WithHTTPClient(srv.Client()),
		WithCacheDir(override),
		WithConcurrency(len(ecosystems)),
		WithRetries(1), // surface the 500 immediately
	)

	start := time.Now()
	if _, err := f.Fetch(context.Background()); err == nil {
		t.Fatal("expected error from failing ecosystem, got nil")
	}
	// Allow generous slack for slow CI: anything well below the slow
	// handler's 5s wait proves siblings were cancelled, not awaited.
	if elapsed := time.Since(start); elapsed > slowDelay/2 {
		t.Errorf("Fetch took %s — siblings were not canceled promptly", elapsed)
	}
}

func TestFetcher_Fetch_RespectsCacheDirOverride(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/ecosystems.txt", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("PyPI\n"))
	})
	mux.HandleFunc("/PyPI/all.zip", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(zipBytes(t, map[string]string{"v.json": `{"id":"x"}`}))
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

	want := filepath.Join(override, "sources", "osv")
	if dir != want {
		t.Errorf("dir = %q, want %q", dir, want)
	}
	if _, err := os.Stat(filepath.Join(dir, "PyPI", "v.json")); err != nil {
		t.Errorf("expected extracted file under override: %v", err)
	}
}

// TestFetcher_Fetch_RenamesEMPTYEcosystemToGeneric pins the rename
// rule for OSV upstream's "[EMPTY]" ecosystem (the bucket OSV uses for
// ecosystem-less generic advisories). The literal sentinel is ugly to
// shell-glob (brackets need escaping) and would leak into
// Provenance.Path / IndexEntry.Source. The fetcher renames the local
// directory to "Generic" while the upstream URL path keeps "[EMPTY]";
// the rename is purely a download-time concern, downstream stages see
// "Generic" verbatim and need no special-case handling.
func TestFetcher_Fetch_RenamesEMPTYEcosystemToGeneric(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/ecosystems.txt", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("[EMPTY]\n"))
	})
	mux.HandleFunc("/[EMPTY]/all.zip", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(zipBytes(t, map[string]string{"CVE-2014-0160.json": `{"id":"CVE-2014-0160"}`}))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("XDG_CACHE_HOME", tmp)

	// [EMPTY] is default-excluded, so the rename path only matters for
	// callers that override the exclusion — construct one explicitly.
	f := New(WithBaseURL(srv.URL), WithHTTPClient(srv.Client()),
		WithExcludedEcosystems([]string{}))
	dir, err := f.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	// Local layout uses Generic, not [EMPTY].
	wantPath := filepath.Join(dir, "Generic", "CVE-2014-0160.json")
	if _, err := os.Stat(wantPath); err != nil {
		t.Errorf("expected %s, stat err = %v", wantPath, err)
	}
	// And [EMPTY] must not exist on disk.
	bad := filepath.Join(dir, "[EMPTY]")
	if _, err := os.Stat(bad); err == nil {
		t.Errorf("[EMPTY] directory should not exist locally; got: %s", bad)
	}
}

func zipBytes(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, body := range entries {
		fw, err := w.Create(name)
		if err != nil {
			t.Fatalf("create entry %s: %v", name, err)
		}
		if _, err := fw.Write([]byte(body)); err != nil {
			t.Fatalf("write entry %s: %v", name, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	return buf.Bytes()
}

// TestFetcher_Fetch_SkipsDefaultExcludedEcosystems pins the curated
// default: noise buckets (GIT / [EMPTY] / GSD / ...) are never
// requested, so neither bandwidth nor disk is spent on them.
func TestFetcher_Fetch_SkipsDefaultExcludedEcosystems(t *testing.T) {
	var excludedRequested atomic.Bool
	mux := http.NewServeMux()
	mux.HandleFunc("/ecosystems.txt", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("PyPI\nGSD\nSUSE\n[EMPTY]\n"))
	})
	mux.HandleFunc("/PyPI/all.zip", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(zipBytes(t, map[string]string{"PYSEC-1.json": `{"id":"PYSEC-1"}`}))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		excludedRequested.Store(true)
		http.Error(w, "should not be requested: "+r.URL.Path, http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("XDG_CACHE_HOME", tmp)

	f := New(WithBaseURL(srv.URL), WithHTTPClient(srv.Client()))
	dir, err := f.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if excludedRequested.Load() {
		t.Error("an excluded ecosystem was requested from upstream")
	}
	if _, err := os.Stat(filepath.Join(dir, "PyPI", "PYSEC-1.json")); err != nil {
		t.Errorf("included ecosystem missing: %v", err)
	}
	for _, eco := range []string{"GSD", "SUSE", "Generic"} {
		if _, err := os.Stat(filepath.Join(dir, eco)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("excluded ecosystem %s present on disk, stat err = %v", eco, err)
		}
	}
}

// TestFetcher_Fetch_WithExcludedEcosystemsOverridesDefault pins the
// override contract: the caller-supplied list REPLACES the default
// (an empty list fetches everything upstream offers).
func TestFetcher_Fetch_WithExcludedEcosystemsOverridesDefault(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/ecosystems.txt", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("PyPI\nSUSE\n"))
	})
	mux.HandleFunc("/PyPI/all.zip", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(zipBytes(t, map[string]string{"PYSEC-1.json": `{"id":"PYSEC-1"}`}))
	})
	mux.HandleFunc("/SUSE/all.zip", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(zipBytes(t, map[string]string{"SUSE-SU-1.json": `{"id":"SUSE-SU-1"}`}))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("XDG_CACHE_HOME", tmp)

	f := New(WithBaseURL(srv.URL), WithHTTPClient(srv.Client()),
		WithExcludedEcosystems([]string{}))
	dir, err := f.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	// Default exclusion is replaced: SUSE (default-excluded) is fetched now.
	if _, err := os.Stat(filepath.Join(dir, "SUSE", "SUSE-SU-1.json")); err != nil {
		t.Errorf("override should fetch SUSE: %v", err)
	}
}

func TestExcluded(t *testing.T) {
	excl := map[string]struct{}{"SUSE": {}, "Wolfi": {}}
	tests := []struct {
		eco  string
		want bool
	}{
		{eco: "SUSE", want: true},
		{eco: "SUSE:15", want: true},   // release-qualified upstream form
		{eco: "openSUSE", want: false}, // prefix must not leak across names
		{eco: "Wolfi", want: true},
		{eco: "PyPI", want: false},
	}
	for _, tc := range tests {
		if got := excluded(excl, tc.eco); got != tc.want {
			t.Errorf("excluded(%q) = %v, want %v", tc.eco, got, tc.want)
		}
	}
}
