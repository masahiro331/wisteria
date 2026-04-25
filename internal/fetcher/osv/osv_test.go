package osv

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
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

// TestFetcher_Fetch_LimitsConcurrency verifies that downloads run in parallel
// but never exceed the configured concurrency cap. The fake server records the
// number of in-flight ecosystem downloads and the test asserts the observed
// peak matches the limit exactly (achievable because we have many more
// ecosystems than the limit).
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
			// Hold the connection long enough for siblings to pile up.
			time.Sleep(50 * time.Millisecond)
			_, _ = w.Write([]byte("payload"))
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

// TestFetcher_Fetch_CancelsSiblingsOnError verifies that when one download
// fails, the in-flight siblings see ctx cancellation rather than running to
// completion.
func TestFetcher_Fetch_CancelsSiblingsOnError(t *testing.T) {
	ecosystems := []string{"fail", "slow1", "slow2", "slow3"}

	var (
		mu       sync.Mutex
		canceled []string
	)
	mux := http.NewServeMux()
	mux.HandleFunc("/ecosystems.txt", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Join(ecosystems, "\n")))
	})
	mux.HandleFunc("/fail/all.zip", func(w http.ResponseWriter, _ *http.Request) {
		// Delay slightly so the slow handlers below are guaranteed to be
		// in their select before the error propagates and cancels gctx.
		time.Sleep(100 * time.Millisecond)
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	for _, eco := range ecosystems[1:] {
		eco := eco
		mux.HandleFunc("/"+eco+"/all.zip", func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-r.Context().Done():
				mu.Lock()
				canceled = append(canceled, eco)
				mu.Unlock()
				return
			case <-time.After(5 * time.Second):
				_, _ = w.Write([]byte("never"))
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
	)

	start := time.Now()
	if _, err := f.Fetch(context.Background()); err == nil {
		t.Fatal("expected error from failing ecosystem, got nil")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("Fetch took %s — siblings were not canceled promptly", elapsed)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(canceled) == 0 {
		t.Error("expected at least one slow ecosystem to observe ctx cancellation")
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
