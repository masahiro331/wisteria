package cache

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDir_DefaultsToUserCacheDir(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", tmp)
	// On macOS, os.UserCacheDir uses $HOME/Library/Caches; override HOME so the
	// returned path is predictable across platforms.
	t.Setenv("HOME", tmp)
	t.Setenv(EnvCacheDir, "")

	got, err := Dir("", "osv")
	if err != nil {
		t.Fatalf("Dir returned error: %v", err)
	}

	if !strings.Contains(got, "wisteria") {
		t.Errorf("expected path to contain %q, got %q", "wisteria", got)
	}
	if filepath.Base(got) != "osv" {
		t.Errorf("expected base dir %q, got %q", "osv", filepath.Base(got))
	}
	info, err := os.Stat(got)
	if err != nil {
		t.Fatalf("expected directory to exist: %v", err)
	}
	if !info.IsDir() {
		t.Errorf("expected %q to be a directory", got)
	}
}

func TestDir_DifferentSourcesReturnDistinctPaths(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", tmp)
	t.Setenv("HOME", tmp)
	t.Setenv(EnvCacheDir, "")

	osvDir, err := Dir("", "osv")
	if err != nil {
		t.Fatalf("Dir(osv): %v", err)
	}
	cveDir, err := Dir("", "cve")
	if err != nil {
		t.Fatalf("Dir(cve): %v", err)
	}
	if osvDir == cveDir {
		t.Errorf("expected distinct paths for different sources, both %q", osvDir)
	}
}

func TestDir_OverrideTakesPrecedenceOverEnvAndDefault(t *testing.T) {
	override := t.TempDir()
	envDir := t.TempDir()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CACHE_HOME", home)
	t.Setenv(EnvCacheDir, envDir)

	got, err := Dir(override, "osv")
	if err != nil {
		t.Fatalf("Dir returned error: %v", err)
	}
	want := filepath.Join(override, "osv")
	if got != want {
		t.Errorf("Dir = %q, want %q", got, want)
	}
}

func TestDir_EnvUsedWhenOverrideEmpty(t *testing.T) {
	envDir := t.TempDir()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CACHE_HOME", home)
	t.Setenv(EnvCacheDir, envDir)

	got, err := Dir("", "cve")
	if err != nil {
		t.Fatalf("Dir returned error: %v", err)
	}
	want := filepath.Join(envDir, "cve")
	if got != want {
		t.Errorf("Dir = %q, want %q", got, want)
	}
}
