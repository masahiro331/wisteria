package cmd

import (
	"bytes"
	"context"
	"testing"
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
