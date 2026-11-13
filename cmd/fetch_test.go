package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/masahiro331/wisteria/internal/fetcher"
)

// TestRoot_CacheDirFlagInheritedBySubcommands ensures the persistent
// --cache-dir flag is exposed on each fetch subcommand, so users can pass
// it before or after the subcommand name.
func TestRoot_CacheDirFlagInheritedBySubcommands(t *testing.T) {
	cases := [][]string{
		{"fetch", "osv"},
		{"fetch", "cve"},
		{"fetch", "kev"},
		{"fetch", "epss"},
		{"fetch", "all"},
	}
	for _, path := range cases {
		t.Run(path[len(path)-1], func(t *testing.T) {
			root := NewRootCmd()
			cmd, _, err := root.Find(path)
			if err != nil {
				t.Fatalf("Find(%v): %v", path, err)
			}
			if cmd.Name() != path[len(path)-1] {
				t.Fatalf("Find(%v) returned %q, want %q", path, cmd.Name(), path[len(path)-1])
			}
			if cmd.Flag(cacheDirFlag) == nil {
				t.Fatalf("--%s not inherited by %v", cacheDirFlag, path)
			}
		})
	}
}

// TestFetch_RetriesAndConcurrencyInheritedBySubcommands ensures the
// fetch-scoped persistent flags reach every fetch subcommand. They are
// scoped to the fetch subtree (not root) because non-HTTP commands like
// `debug index` would expose them as no-op flags otherwise.
func TestFetch_RetriesAndConcurrencyInheritedBySubcommands(t *testing.T) {
	flags := []string{retriesFlag, concurrencyFlag}
	cases := [][]string{
		{"fetch", "osv"},
		{"fetch", "cve"},
		{"fetch", "kev"},
		{"fetch", "epss"},
		{"fetch", "all"},
	}
	for _, path := range cases {
		t.Run(path[len(path)-1], func(t *testing.T) {
			root := NewRootCmd()
			cmd, _, err := root.Find(path)
			if err != nil {
				t.Fatalf("Find(%v): %v", path, err)
			}
			for _, f := range flags {
				if cmd.Flag(f) == nil {
					t.Errorf("--%s not inherited by %v", f, path)
				}
			}
		})
	}
}

// TestDebug_DoesNotExposeFetchOnlyFlags is the regression test for
// scoping --retries / --concurrency: they only make sense for HTTP
// fetchers, so non-fetch subcommands must not surface them.
func TestDebug_DoesNotExposeFetchOnlyFlags(t *testing.T) {
	flags := []string{retriesFlag, concurrencyFlag}
	root := NewRootCmd()
	cmd, _, err := root.Find([]string{"debug", "index"})
	if err != nil {
		t.Fatalf("Find debug index: %v", err)
	}
	for _, f := range flags {
		if cmd.Flag(f) != nil {
			t.Errorf("--%s leaked into debug index", f)
		}
	}
}

// TestRoot_CacheDirFlagParses checks that --cache-dir is parsed off the
// command line and reaches the subcommand's flag set.
func TestRoot_CacheDirFlagParses(t *testing.T) {
	root := NewRootCmd()
	root.SetArgs([]string{"fetch", "--cache-dir", "/tmp/example", "--help"})
	root.SetOut(new(bytes.Buffer))
	root.SetErr(new(bytes.Buffer))
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	cmd, _, err := root.Find([]string{"fetch"})
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	got, err := cmd.Flags().GetString(cacheDirFlag)
	if err != nil {
		t.Fatalf("GetString: %v", err)
	}
	if got != "/tmp/example" {
		t.Errorf("cache-dir = %q, want %q", got, "/tmp/example")
	}
}

// TestFetch_OSVExcludeFlagInherited ensures --osv-exclude reaches the
// osv and all subcommands (it lives on the fetch subtree like the other
// HTTP knobs).
func TestFetch_OSVExcludeFlagInherited(t *testing.T) {
	for _, path := range [][]string{{"fetch", "osv"}, {"fetch", "all"}} {
		root := NewRootCmd()
		cmd, _, err := root.Find(path)
		if err != nil {
			t.Fatalf("Find(%v): %v", path, err)
		}
		if cmd.Flag(osvExcludeFlag) == nil {
			t.Fatalf("--%s not inherited by %v", osvExcludeFlag, path)
		}
	}
}

func TestNormalizeExcludes(t *testing.T) {
	if got := normalizeExcludes([]string{""}); len(got) != 0 || got == nil {
		t.Errorf(`normalizeExcludes([""]) = %#v, want non-nil empty slice`, got)
	}
	if got := normalizeExcludes([]string{"GIT", "", "SUSE"}); len(got) != 2 {
		t.Errorf("normalizeExcludes dropped wrong entries: %v", got)
	}
}

type stubFetcher struct {
	name  string
	err   error
	calls *[]string
}

func (s stubFetcher) Name() string { return s.name }

func (s stubFetcher) Fetch(context.Context) (string, error) {
	*s.calls = append(*s.calls, s.name)
	return "/tmp/" + s.name, s.err
}

func stubSource(name string, err error, optional bool, calls *[]string) fetchSource {
	return fetchSource{optional: optional, factory: func(fetchOptions) fetcher.Fetcher {
		return stubFetcher{name: name, err: err, calls: calls}
	}}
}

// An optional source that fails (or is not configured) is a warning: the
// other sources still run and fetch all succeeds.
func TestFetchAll_OptionalSourceFailureContinues(t *testing.T) {
	for _, failure := range []error{errors.New("status 503"), fmt.Errorf("no token: %w", fetcher.ErrNotConfigured)} {
		var calls []string
		var out, errOut bytes.Buffer
		sources := []fetchSource{
			stubSource("kev", nil, false, &calls),
			stubSource("vulncheck-kev", failure, true, &calls),
			stubSource("epss", nil, false, &calls),
		}
		if err := fetchAll(context.Background(), fetchOptions{}, sources, &out, &errOut); err != nil {
			t.Fatalf("fetchAll: %v", err)
		}
		if strings.Join(calls, ",") != "kev,vulncheck-kev,epss" {
			t.Errorf("calls = %v", calls)
		}
		if !strings.Contains(errOut.String(), "warning: vulncheck-kev:") {
			t.Errorf("stderr = %q, want a warning", errOut.String())
		}
	}
}

func TestFetchAll_RequiredSourceFailureStops(t *testing.T) {
	var calls []string
	sources := []fetchSource{
		stubSource("kev", errors.New("boom"), false, &calls),
		stubSource("epss", nil, false, &calls),
	}
	err := fetchAll(context.Background(), fetchOptions{}, sources, io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "kev: boom") || len(calls) != 1 {
		t.Errorf("err = %v, calls = %v", err, calls)
	}
}

// fetch all includes VulnCheck KEV, as the one optional source.
func TestAllSources_VulnCheckKEVIsOptional(t *testing.T) {
	var names []string
	for _, s := range allSources {
		f := s.factory(fetchOptions{})
		if s.optional != (f.Name() == "vulncheck-kev") {
			t.Errorf("%s optional = %v", f.Name(), s.optional)
		}
		names = append(names, f.Name())
	}
	if strings.Join(names, ",") != "osv,cve,kev,vulncheck-kev,epss,exploitdb" {
		t.Errorf("sources = %v", names)
	}
}

// fetch vulncheck-kev without a token warns and exits cleanly.
func TestFetchVulnCheckKEV_NoTokenWarns(t *testing.T) {
	t.Setenv("VULNCHECK_API_TOKEN", "")
	root := NewRootCmd()
	var errOut bytes.Buffer
	root.SetErr(&errOut)
	root.SetOut(io.Discard)
	root.SetArgs([]string{"fetch", "vulncheck-kev", "--cache-dir", t.TempDir()})
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !strings.Contains(errOut.String(), "warning: vulncheck-kev:") {
		t.Errorf("stderr = %q", errOut.String())
	}
}

type blockingFetcher struct{ calls *[]string }

func (blockingFetcher) Name() string { return "vulncheck-kev" }

func (b blockingFetcher) Fetch(ctx context.Context) (string, error) {
	*b.calls = append(*b.calls, "vulncheck-kev")
	<-ctx.Done()
	return "", ctx.Err()
}

// An optional source that hangs is cut off after optionalSourceTimeout and
// the rest of fetch all still runs.
func TestFetchAll_OptionalSourceTimesOut(t *testing.T) {
	old := optionalSourceTimeout
	optionalSourceTimeout = 50 * time.Millisecond
	t.Cleanup(func() { optionalSourceTimeout = old })

	var calls []string
	var errOut bytes.Buffer
	sources := []fetchSource{
		{optional: true, factory: func(fetchOptions) fetcher.Fetcher { return blockingFetcher{calls: &calls} }},
		stubSource("epss", nil, false, &calls),
	}
	done := make(chan error, 1)
	go func() { done <- fetchAll(context.Background(), fetchOptions{}, sources, io.Discard, &errOut) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("fetchAll: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("fetchAll hung on the optional source")
	}
	if strings.Join(calls, ",") != "vulncheck-kev,epss" || !strings.Contains(errOut.String(), "warning: vulncheck-kev:") {
		t.Errorf("calls = %v, stderr = %q", calls, errOut.String())
	}
}
