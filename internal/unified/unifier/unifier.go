// Package unifier implements Stage 2 of the unified-advisory pipeline:
// per-PrimaryID semantic merge of OSV / CVE5 advisories. The package is
// split across files by concern:
//
//   - priority.go     — shared §8.1 vendor priority array
//   - references.go   — mergeReferences (§8.2)
//   - descriptions.go — mergeDescriptions (§8.3, parallel hold)
//   - severities.go   — mergeSeverities (§8.4)
//   - affected.go     — mergeAffected (§8.5, parallel hold)
//   - convert.go      — upstream → unified shape adapters
//   - unifier.go      — public per-PrimaryID orchestration used by debug
//
// #16 added References + Severities; #17 adds Descriptions + Affected.
// The production Unify entrypoint (full-index orchestration + writer
// coordination) lands in #19.
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

// MergePrimary parses each IndexEntry under primaryID and applies the
// per-field merge rules (References §8.2, Descriptions §8.3, Severities
// §8.4, Affected §8.5). SourceIDs / KEV / EPSS remain zero — those land
// in #19 (SourceIDs collection during full-index orchestration), #20,
// and #21 respectively.
//
// CVE5 records contribute one Provenance per container (the CNA plus
// each ADP, e.g. CISA Vulnrichment). ADP IDs are suffixed with
// "#adp:<shortName>" so downstream sorts treat them as parallel siblings
// of the CNA without losing the source-of-record distinction.
//
// Used by `wisteria debug unify --id` to validate merge rules against
// real source files; production wiring lives in #19.
func MergePrimary(ctx context.Context, sourcesRoot, primaryID string, entries []unified.IndexEntry) (unified.UnifiedAdvisory, error) {
	var (
		refs        []unified.Reference
		descs       []descriptionItem
		sevs        []severityItem
		affs        []affectedItem
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
			source := SourceTag(e.Kind, e.Source)
			refs = append(refs, OSVReferences(rec.References)...)
			descs = append(descs, OSVDescriptions(rec, prov, source)...)
			sevs = append(sevs, OSVSeverities(rec.Severity, prov, source)...)
			affs = append(affs, OSVAffectedRecords(rec.Affected, prov, source)...)
		case unified.SourceCVE:
			rec, err := readCVE(path)
			if err != nil {
				return unified.UnifiedAdvisory{}, fmt.Errorf("%s: %w", e.Path, err)
			}
			cna := rec.Containers.CNA
			refs = append(refs, CVEReferences(cna.References)...)
			descs = append(descs, CVEDescriptions(cna.Descriptions, prov)...)
			sevs = append(sevs, CVEMetrics(cna.Metrics, prov)...)
			affs = append(affs, CVEAffectedRecords(cna.Affected, prov)...)
			for i, adp := range rec.Containers.ADP {
				adpProv := ADPProvenance(prov, adp, i)
				provenances = append(provenances, adpProv)
				refs = append(refs, CVEReferences(adp.References)...)
				descs = append(descs, CVEDescriptions(adp.Descriptions, adpProv)...)
				sevs = append(sevs, CVEMetrics(adp.Metrics, adpProv)...)
				affs = append(affs, CVEAffectedRecords(adp.Affected, adpProv)...)
			}
		default:
			return unified.UnifiedAdvisory{}, fmt.Errorf("%s: unsupported kind %q", e.Path, e.Kind)
		}
	}
	return unified.UnifiedAdvisory{
		PrimaryID:    primaryID,
		Descriptions: mergeDescriptions(descs),
		References:   mergeReferences(refs),
		Severities:   mergeSeverities(sevs),
		Affected:     mergeAffected(affs),
		Provenances:  provenances,
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
