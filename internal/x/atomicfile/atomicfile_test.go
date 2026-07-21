package atomicfile_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/masahiro331/wisteria/internal/x/atomicfile"
)

func TestWrite_CreatesFileWithBody(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "out.json")
	if err := atomicfile.Write(dest, []byte(`{"a":1}`)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != `{"a":1}` {
		t.Errorf("body = %q", got)
	}
}

func TestWrite_ReplacesExistingFile(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "out.json")
	if err := os.WriteFile(dest, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := atomicfile.Write(dest, []byte("new")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got, _ := os.ReadFile(dest)
	if string(got) != "new" {
		t.Errorf("body = %q, want new", got)
	}
}

func TestWrite_LeavesNoTempFileBehind(t *testing.T) {
	dir := t.TempDir()
	if err := atomicfile.Write(filepath.Join(dir, "out.json"), []byte("x")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "out.json" {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Errorf("dir contents = %v, want only out.json", names)
	}
}

func TestWrite_ErrorsWhenParentMissing(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "missing", "out.json")
	if err := atomicfile.Write(dest, []byte("x")); err == nil {
		t.Fatal("expected error when parent dir is missing")
	}
}
