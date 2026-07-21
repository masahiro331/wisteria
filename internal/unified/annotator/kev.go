// Package annotator is Stage 4 of the unified-advisory pipeline. It
// reads per-source signal catalogs (KEV, EPSS, Exploit-DB) and writes
// their fields back into the matching <outDir>/cve/<year>/<CVE-ID>.json
// files produced by Stage 3.
//
// Annotators run after writer.Write has finished, so the unified files
// already exist on disk. A catalog entry whose CVE-ID has no matching
// unified file is silently skipped — synthesizing a signal-only
// UnifiedAdvisory is an open question (see docs/ROADMAP.md Phase 1
// "Signal-only UnifiedAdvisory").
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

	"github.com/masahiro331/wisteria/internal/unified/kev"
	"github.com/masahiro331/wisteria/pkg/advisory"
)

const kevCatalogRelPath = "kev/known_exploited_vulnerabilities.json"

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
	return updateCVE(outDir, v.CVEID, func(rec *advisory.UnifiedAdvisory) {
		rec.KEV = kevRecord(catalogRelPath, v)
	})
}

// kevRecord copies the upstream KEV vulnerability into the unified shape.
// Provenance.Path uses the catalog's path relative to sourcesRoot — same
// convention as walker.IndexEntry.Path — so debug tooling can resolve
// any KEV field back to its source row.
func kevRecord(catalogRelPath string, v kev.Vulnerability) *advisory.KEVRecord {
	rec := &advisory.KEVRecord{
		From: advisory.Provenance{
			Kind: advisory.SourceKEV,
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
