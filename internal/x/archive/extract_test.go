package archive

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestZip_ExtractsAllEntries(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "all.zip")
	writeZip(t, archive, map[string]string{
		"a.json":     `{"id":1}`,
		"sub/b.json": `{"id":2}`,
	})

	dest := t.TempDir()
	if err := Zip(archive, dest); err != nil {
		t.Fatalf("Zip: %v", err)
	}

	want := map[string]string{
		filepath.Join(dest, "a.json"):        `{"id":1}`,
		filepath.Join(dest, "sub", "b.json"): `{"id":2}`,
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
}

func TestZip_RejectsZipSlip(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "evil.zip")
	writeZip(t, archive, map[string]string{
		"../escape.json": `nope`,
	})

	dest := t.TempDir()
	err := Zip(archive, dest)
	if err == nil {
		t.Fatal("expected error for path traversal entry, got nil")
	}
	if !strings.Contains(err.Error(), "unsafe") {
		t.Errorf("expected error to mention unsafe path, got %v", err)
	}
}

func TestTarGz_ExtractsAllEntries(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "main.tar.gz")
	writeTarGz(t, archive, map[string]string{
		"root/file.txt":     "hello",
		"root/sub/data.txt": "world",
	})

	dest := t.TempDir()
	if err := TarGz(archive, dest); err != nil {
		t.Fatalf("TarGz: %v", err)
	}

	want := map[string]string{
		filepath.Join(dest, "root", "file.txt"):        "hello",
		filepath.Join(dest, "root", "sub", "data.txt"): "world",
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
}

func TestTarGz_RejectsTarSlip(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "evil.tar.gz")
	writeTarGz(t, archive, map[string]string{
		"../escape.txt": "nope",
	})

	dest := t.TempDir()
	err := TarGz(archive, dest)
	if err == nil {
		t.Fatal("expected error for path traversal entry, got nil")
	}
	if !strings.Contains(err.Error(), "unsafe") {
		t.Errorf("expected error to mention unsafe path, got %v", err)
	}
}

func writeZip(t *testing.T, path string, entries map[string]string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create zip: %v", err)
	}
	defer f.Close()
	w := zip.NewWriter(f)
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
}

func writeTarGz(t *testing.T, path string, entries map[string]string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create tar.gz: %v", err)
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for name, body := range entries {
		hdr := &tar.Header{
			Name: name,
			Mode: 0o644,
			Size: int64(len(body)),
		}
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
}
