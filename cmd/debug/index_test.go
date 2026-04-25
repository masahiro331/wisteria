package debug_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/masahiro331/wisteria/cmd"
)

// writeFile creates parent dirs and writes body to <root>/<rel>. Tests
// only use it for OSV / CVE5 fixtures.
func writeFile(t *testing.T, root, rel, body string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// fixtureCacheDir lays out a minimal sources/ tree under a tmp cache-dir
// and returns its path. Two OSV files (one CVE-aliased, one standalone)
// plus one CVE5 file — enough to exercise distribution + --id paths.
func fixtureCacheDir(t *testing.T) string {
	t.Helper()
	cacheDir := t.TempDir()
	src := filepath.Join(cacheDir, "sources")
	writeFile(t, src, "osv/PyPI/PYSEC-2024-1.json", `{"id":"PYSEC-2024-1","aliases":["CVE-2024-0001"]}`)
	writeFile(t, src, "osv/Go/GO-2024-1234.json", `{"id":"GO-2024-1234"}`)
	writeFile(t, src, "cve/cvelistV5-main/cves/2024/0xxx/CVE-2024-0001.json", "{}")
	return cacheDir
}

func runDebugIndex(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	root := cmd.NewRootCmd()
	full := append([]string{"debug", "index"}, args...)
	root.SetArgs(full)
	var out, errBuf bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errBuf)
	err = root.ExecuteContext(context.Background())
	return out.String(), errBuf.String(), err
}

func TestDebugIndex_Distribution(t *testing.T) {
	cacheDir := fixtureCacheDir(t)

	stdout, _, err := runDebugIndex(t, "--cache-dir", cacheDir)
	if err != nil {
		t.Fatalf("debug index: %v", err)
	}

	// 2 OSV PrimaryIDs (CVE-2024-0001 from alias + GO-2024-1234 standalone)
	// + 0 extra from CVE5 (it converges with CVE-2024-0001) = 2 total.
	wantSubs := []string{
		"PrimaryIDs: 2",
		"osv: 2",
		"cve: 1",
		"PyPI: 1",
		"Go: 1",
	}
	for _, s := range wantSubs {
		if !strings.Contains(stdout, s) {
			t.Errorf("output missing %q\nfull output:\n%s", s, stdout)
		}
	}
}

func TestDebugIndex_IDFound(t *testing.T) {
	cacheDir := fixtureCacheDir(t)

	stdout, _, err := runDebugIndex(t, "--cache-dir", cacheDir, "--id", "CVE-2024-0001")
	if err != nil {
		t.Fatalf("debug index --id: %v", err)
	}

	wantSubs := []string{
		"CVE-2024-0001",
		"osv/PyPI/PYSEC-2024-1.json",
		"cve/cvelistV5-main/cves/2024/0xxx/CVE-2024-0001.json",
	}
	for _, s := range wantSubs {
		if !strings.Contains(stdout, s) {
			t.Errorf("output missing %q\nfull output:\n%s", s, stdout)
		}
	}
}

func TestDebugIndex_IDStandalone(t *testing.T) {
	cacheDir := fixtureCacheDir(t)

	stdout, _, err := runDebugIndex(t, "--cache-dir", cacheDir, "--id", "GO-2024-1234")
	if err != nil {
		t.Fatalf("debug index --id GO-*: %v", err)
	}
	if !strings.Contains(stdout, "osv/Go/GO-2024-1234.json") {
		t.Errorf("standalone path missing\nfull output:\n%s", stdout)
	}
}

func TestDebugIndex_IDNotFoundExitsNonZero(t *testing.T) {
	cacheDir := fixtureCacheDir(t)

	_, _, err := runDebugIndex(t, "--cache-dir", cacheDir, "--id", "CVE-9999-9999")
	if err == nil {
		t.Fatal("debug index --id <unknown>: expected error, got nil")
	}
}
