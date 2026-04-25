// Package extract unpacks compressed archives into a destination directory.
// Both Zip and TarGz reject entries whose resolved path escapes the
// destination root (zip-slip / tar-slip).
package extract

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Zip extracts every file in archive into dest, mirroring the archive's
// internal directory structure.
func Zip(archive, dest string) error {
	r, err := zip.OpenReader(archive)
	if err != nil {
		return fmt.Errorf("open zip %s: %w", archive, err)
	}
	defer r.Close()

	for _, entry := range r.File {
		if err := writeZipEntry(entry, dest); err != nil {
			return err
		}
	}
	return nil
}

func writeZipEntry(entry *zip.File, dest string) error {
	target, err := safeJoin(dest, entry.Name)
	if err != nil {
		return err
	}
	if entry.FileInfo().IsDir() {
		return os.MkdirAll(target, 0o755)
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	src, err := entry.Open()
	if err != nil {
		return fmt.Errorf("open entry %s: %w", entry.Name, err)
	}
	defer src.Close()
	return copyTo(target, src)
}

// TarGz extracts every file in a gzip-compressed tar archive into dest.
func TarGz(archive, dest string) error {
	f, err := os.Open(archive)
	if err != nil {
		return fmt.Errorf("open tar.gz %s: %w", archive, err)
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("gzip reader: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read tar: %w", err)
		}
		if err := writeTarEntry(hdr, tr, dest); err != nil {
			return err
		}
	}
}

func writeTarEntry(hdr *tar.Header, tr *tar.Reader, dest string) error {
	target, err := safeJoin(dest, hdr.Name)
	if err != nil {
		return err
	}
	switch hdr.Typeflag {
	case tar.TypeDir:
		return os.MkdirAll(target, 0o755)
	case tar.TypeReg:
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		return copyTo(target, tr)
	default:
		// Skip symlinks, devices, etc. — the upstream archives we target
		// don't use them, and supporting them safely is out of scope.
		return nil
	}
}

func copyTo(target string, src io.Reader) error {
	out, err := os.Create(target)
	if err != nil {
		return fmt.Errorf("create %s: %w", target, err)
	}
	defer out.Close()
	if _, err := io.Copy(out, src); err != nil {
		return fmt.Errorf("write %s: %w", target, err)
	}
	return nil
}

// safeJoin joins name onto root and rejects results that escape root, so
// crafted archives can't drop files outside the destination.
func safeJoin(root, name string) (string, error) {
	cleaned := filepath.Clean(name)
	target := filepath.Join(root, cleaned)
	rel, err := filepath.Rel(root, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("unsafe entry path %q", name)
	}
	return target, nil
}
