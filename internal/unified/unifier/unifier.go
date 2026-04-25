// Package unifier implements Stage 2 of the unified-advisory pipeline:
// per-PrimaryID semantic merge of OSV / CVE5 advisories. The package is
// split across files by concern:
//
//   - priority.go     — shared §8.1 vendor priority array
//   - references.go   — mergeReferences (§8.2)
//   - severities.go   — mergeSeverities (§8.4)
//   - convert.go      — upstream → unified shape adapters
//   - unifier.go      — public per-PrimaryID orchestration used by debug
//
// #16 implements References + Severities only. Descriptions / Affected
// merge and the production Unify entrypoint land in #17 / #19.
package unifier

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/masahiro331/wisteria/internal/unified"
	"github.com/masahiro331/wisteria/internal/unified/cve"
	"github.com/masahiro331/wisteria/internal/unified/osv"
)

// MergePrimary parses each IndexEntry under primaryID, applies the
// References / Severities merge rules, and returns a partial
// UnifiedAdvisory. Descriptions / Affected / SourceIDs / KEV / EPSS are
// left zero — they get populated by later issues (#17, #20, #21).
//
// Used by `wisteria debug unify --id` to validate merge rules against
// real source files; production wiring lives in #19.
func MergePrimary(ctx context.Context, sourcesRoot, primaryID string, entries []unified.IndexEntry) (unified.UnifiedAdvisory, error) {
	var (
		refs        []unified.Reference
		sevs        []severityItem
		provenances []unified.Provenance
	)
	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return unified.UnifiedAdvisory{}, err
		}
		path := filepath.Join(sourcesRoot, e.Path)
		prov := unified.Provenance{Kind: e.Kind, Path: e.Path, ID: e.SourceID}
		provenances = append(provenances, prov)
		switch e.Kind {
		case unified.SourceOSV:
			rec, err := readOSV(path)
			if err != nil {
				return unified.UnifiedAdvisory{}, fmt.Errorf("%s: %w", e.Path, err)
			}
			refs = append(refs, OSVReferences(rec.References)...)
			sevs = append(sevs, OSVSeverities(rec.Severity, prov, SourceTag(e.Kind, e.Source))...)
		case unified.SourceCVE:
			rec, err := readCVE(path)
			if err != nil {
				return unified.UnifiedAdvisory{}, fmt.Errorf("%s: %w", e.Path, err)
			}
			refs = append(refs, CVEReferences(rec.Containers.CNA.References)...)
			sevs = append(sevs, CVEMetrics(rec.Containers.CNA.Metrics, prov)...)
		default:
			return unified.UnifiedAdvisory{}, fmt.Errorf("%s: unsupported kind %q", e.Path, e.Kind)
		}
	}
	return unified.UnifiedAdvisory{
		PrimaryID:   primaryID,
		References:  mergeReferences(refs),
		Severities:  mergeSeverities(sevs),
		Provenances: provenances,
	}, nil
}

func readOSV(path string) (osv.Record, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return osv.Record{}, err
	}
	var r osv.Record
	if err := json.Unmarshal(b, &r); err != nil {
		return osv.Record{}, err
	}
	return r, nil
}

func readCVE(path string) (cve.Record, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return cve.Record{}, err
	}
	var r cve.Record
	if err := json.Unmarshal(b, &r); err != nil {
		return cve.Record{}, err
	}
	return r, nil
}
