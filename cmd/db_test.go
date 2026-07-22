package cmd_test

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/masahiro331/wisteria/cmd"
)

// dbFixture builds a queryable unified tree by running the real unify
// pipeline over a minimal sources tree, so `wisteria db` is tested
// against exactly what production writes (records + Stage 5 index).
func dbFixture(t *testing.T) string {
	t.Helper()
	cacheDir := t.TempDir()
	src := filepath.Join(cacheDir, "sources")
	writeFile(t, src, "osv/PyPI/PYSEC-2024-1.json",
		`{"id":"PYSEC-2024-1","aliases":["CVE-2024-0001"],"summary":"Python advisory",`+
			`"affected":[{"package":{"ecosystem":"PyPI","name":"django"}}]}`)
	writeFile(t, src, "cve/cvelistV5-main/cves/2024/0xxx/CVE-2024-0001.json",
		`{"cveMetadata":{"cveId":"CVE-2024-0001"},"containers":{"cna":{"descriptions":[{"lang":"en","value":"CNA"}]}}}`)
	if _, _, err := runCLI(t, "unify", "--cache-dir", cacheDir); err != nil {
		t.Fatalf("unify fixture: %v", err)
	}
	return cacheDir
}

func runCLI(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	root := cmd.NewRootCmd()
	root.SetArgs(args)
	var out, errBuf bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errBuf)
	err = root.ExecuteContext(context.Background())
	return out.String(), errBuf.String(), err
}

func TestDBFind_ByPrimaryID(t *testing.T) {
	cacheDir := dbFixture(t)

	out, _, err := runCLI(t, "db", "find", "--cache-dir", cacheDir, "CVE-2024-0001")
	if err != nil {
		t.Fatalf("db find: %v", err)
	}
	var rec struct {
		PrimaryID string `json:"primary_id"`
	}
	if err := json.Unmarshal([]byte(out), &rec); err != nil {
		t.Fatalf("output is not one JSON object: %v\n%s", err, out)
	}
	if rec.PrimaryID != "CVE-2024-0001" {
		t.Errorf("primary_id = %q", rec.PrimaryID)
	}
}

func TestDBFind_ByAlias(t *testing.T) {
	cacheDir := dbFixture(t)

	out, _, err := runCLI(t, "db", "find", "--cache-dir", cacheDir, "PYSEC-2024-1")
	if err != nil {
		t.Fatalf("db find alias: %v", err)
	}
	if !strings.Contains(out, `"primary_id": "CVE-2024-0001"`) {
		t.Errorf("alias lookup output:\n%s", out)
	}
}

func TestDBFind_NotFoundIsError(t *testing.T) {
	cacheDir := dbFixture(t)

	_, _, err := runCLI(t, "db", "find", "--cache-dir", cacheDir, "CVE-1999-9999")
	if err == nil {
		t.Fatal("expected non-nil error for unknown id")
	}
}

func TestDBGet_ReturnsExactlyOneRecord(t *testing.T) {
	cacheDir := dbFixture(t)

	out, _, err := runCLI(t, "db", "get", "--cache-dir", cacheDir, "CVE-2024-0001")
	if err != nil {
		t.Fatalf("db get: %v", err)
	}
	var rec struct {
		PrimaryID string `json:"primary_id"`
	}
	if err := json.Unmarshal([]byte(out), &rec); err != nil {
		t.Fatalf("output is not one JSON object: %v\n%s", err, out)
	}
	if rec.PrimaryID != "CVE-2024-0001" {
		t.Errorf("primary_id = %q", rec.PrimaryID)
	}
}

func TestDBGet_NotFoundIsError(t *testing.T) {
	cacheDir := dbFixture(t)

	if _, _, err := runCLI(t, "db", "get", "--cache-dir", cacheDir, "CVE-1999-9999"); err == nil {
		t.Fatal("expected non-nil error for unknown id")
	}
}

func TestDBPackage_Hit(t *testing.T) {
	cacheDir := dbFixture(t)

	out, _, err := runCLI(t, "db", "package", "--cache-dir", cacheDir, "PyPI", "django")
	if err != nil {
		t.Fatalf("db package: %v", err)
	}
	if !strings.Contains(out, `"primary_id": "CVE-2024-0001"`) {
		t.Errorf("package lookup output:\n%s", out)
	}
}

func TestDBPackage_NoMatchIsError(t *testing.T) {
	cacheDir := dbFixture(t)

	_, _, err := runCLI(t, "db", "package", "--cache-dir", cacheDir, "PyPI", "no-such-package")
	if err == nil {
		t.Fatal("expected non-nil error for no matches")
	}
}

func TestDBFind_ExplicitDSNOverridesCacheDir(t *testing.T) {
	cacheDir := dbFixture(t)

	out, _, err := runCLI(t, "db", "find",
		"--dsn", "fs://"+filepath.Join(cacheDir, "unified"), "CVE-2024-0001")
	if err != nil {
		t.Fatalf("db find --dsn: %v", err)
	}
	if !strings.Contains(out, `"primary_id": "CVE-2024-0001"`) {
		t.Errorf("dsn lookup output:\n%s", out)
	}
}
