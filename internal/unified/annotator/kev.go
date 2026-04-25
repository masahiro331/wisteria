// Package annotator is Stage 4 of the unified-advisory pipeline. It
// reads per-source signal catalogs (KEV, EPSS) and writes their fields
// back into the matching <outDir>/cve/<year>/<CVE-ID>.json files
// produced by Stage 3.
//
// Annotators run after writer.Write has finished, so the unified files
// already exist on disk. A KEV / EPSS entry whose CVE-ID has no matching
// unified file is silently skipped — signal-only handling (creating a
// stub UnifiedAdvisory from KEV/EPSS alone) is deferred per design §Q3.
//
// A missing source catalog (e.g. user ran `wisteria unify` without
// `wisteria fetch kev`) is a no-op rather than an error: not every
// pipeline run needs every signal.
package annotator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/masahiro331/wisteria/internal/unified"
	"github.com/masahiro331/wisteria/internal/unified/kev"
)

const (
	kevCatalogRelPath = "kev/known_exploited_vulnerabilities.json"
	cveBucket         = "cve"
)

// cveIDPattern matches the CVE-ID shape Stage 3 routes to cve/<year>/.
// The capture group exposes the year for path resolution.
var cveIDPattern = regexp.MustCompile(`^CVE-(\d{4})-\d+$`)

// AnnotateKEV reads <sourcesRoot>/kev/known_exploited_vulnerabilities.json
// and, for every entry whose CVE-ID has a matching unified file under
// <outDir>/cve/<year>/, sets UnifiedAdvisory.KEV and rewrites the file.
// Missing target → skip; missing catalog → no-op.
func AnnotateKEV(ctx context.Context, sourcesRoot, outDir string) error {
	catalogPath := filepath.Join(sourcesRoot, kevCatalogRelPath)
	body, err := os.ReadFile(catalogPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("annotator: read %s: %w", catalogPath, err)
	}
	var cat kev.Catalog
	if err := json.Unmarshal(body, &cat); err != nil {
		return fmt.Errorf("annotator: parse %s: %w", catalogPath, err)
	}
	for _, v := range cat.Vulnerabilities {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := applyKEVEntry(outDir, kevCatalogRelPath, v); err != nil {
			return err
		}
	}
	return nil
}

// applyKEVEntry resolves the unified file for one KEV vulnerability and,
// when present, merges the KEV record into it. Missing target is a
// silent skip — see package doc.
func applyKEVEntry(outDir, catalogRelPath string, v kev.Vulnerability) error {
	path, ok := unifiedCVEPath(outDir, v.CVEID)
	if !ok {
		return nil
	}
	rec, ok, err := readUnified(path)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	rec.KEV = kevRecord(catalogRelPath, v)
	return writeUnified(path, rec)
}

// unifiedCVEPath returns the per-record path for a CVE-ID. Returns
// (_, false) when the ID does not match the CVE-YYYY-NNNN shape that
// Stage 3 routes to cve/<year>/; KEV / EPSS only key by CVE-ID, so a
// non-CVE input means "no target", not an error.
func unifiedCVEPath(outDir, cveID string) (string, bool) {
	m := cveIDPattern.FindStringSubmatch(cveID)
	if m == nil {
		return "", false
	}
	return filepath.Join(outDir, cveBucket, m[1], cveID+".json"), true
}

// readUnified loads one Stage 3 file. (_, false, nil) means the file is
// absent — the caller skips. Any other I/O or decode error is returned.
func readUnified(path string) (unified.UnifiedAdvisory, bool, error) {
	body, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return unified.UnifiedAdvisory{}, false, nil
	}
	if err != nil {
		return unified.UnifiedAdvisory{}, false, fmt.Errorf("annotator: read %s: %w", path, err)
	}
	var rec unified.UnifiedAdvisory
	if err := json.Unmarshal(body, &rec); err != nil {
		return unified.UnifiedAdvisory{}, false, fmt.Errorf("annotator: decode %s: %w", path, err)
	}
	return rec, true, nil
}

// writeUnified rewrites a Stage 3 file in place. Plain os.WriteFile —
// not atomic — because Stage 4 always runs as part of `wisteria unify`
// after Stage 3, so a crashed mid-write file is rebuilt on the next
// pipeline run from upstream sources (which the user keeps under git).
func writeUnified(path string, rec unified.UnifiedAdvisory) error {
	body, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return fmt.Errorf("annotator: marshal %s: %w", path, err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		return fmt.Errorf("annotator: write %s: %w", path, err)
	}
	return nil
}

// kevRecord copies the upstream KEV vulnerability into the unified shape.
// Provenance.Path uses the catalog's path relative to sourcesRoot — same
// convention as walker.IndexEntry.Path — so debug tooling can resolve
// any KEV field back to its source row.
func kevRecord(catalogRelPath string, v kev.Vulnerability) *unified.KEVRecord {
	rec := &unified.KEVRecord{
		From: unified.Provenance{
			Kind: unified.SourceKEV,
			Path: catalogRelPath,
			ID:   v.CVEID,
		},
		VendorProject:              v.VendorProject,
		Product:                    v.Product,
		VulnerabilityName:          v.VulnerabilityName,
		ShortDescription:           v.ShortDescription,
		RequiredAction:             v.RequiredAction,
		KnownRansomwareCampaignUse: v.KnownRansomwareCampaignUse,
		Notes:                      v.Notes,
		CWEs:                       v.CWEs,
	}
	if !v.DateAdded.IsZero() {
		rec.DateAdded = v.DateAdded.Format("2006-01-02")
	}
	if !v.DueDate.IsZero() {
		rec.DueDate = v.DueDate.Format("2006-01-02")
	}
	return rec
}
