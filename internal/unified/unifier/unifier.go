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
//   - unifier.go      — MergePrimary: parse + merge for one PrimaryID.
//
// Stage-level orchestration (PrimaryID fan-out, error policy, writer
// hand-off) lives in cmd/unify so production can stream MergePrimary's
// output straight to disk without buffering 100k+ records in memory.
// SourceIDs (alias dedup) is collected inside MergePrimary in the same
// pass that reads each OSV file. KEV / EPSS attachment is Stage 4.
package unifier

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/masahiro331/wisteria/internal/unified"
	"github.com/masahiro331/wisteria/internal/unified/cve"
	"github.com/masahiro331/wisteria/internal/unified/osv"
	"github.com/masahiro331/wisteria/internal/unified/osv/ecosystem"
)

// MergePrimary parses each IndexEntry under primaryID and applies the
// per-field merge rules (References §8.2, Descriptions §8.3, Severities
// §8.4, Affected §8.5). SourceIDs (every alias other than the PrimaryID,
// deduped + lex-sorted) are collected here in the same pass so each OSV
// file is read at most once. KEV / EPSS / Exploit-DB are not merged
// here — they are attached in Stage 4 (annotator package).
//
// CVE5 records contribute one Provenance per container (the CNA plus
// each ADP, e.g. CISA Vulnrichment). ADP IDs are suffixed with
// "#adp:<shortName>" so downstream sorts treat them as parallel siblings
// of the CNA without losing the source-of-record distinction.
func MergePrimary(ctx context.Context, sourcesRoot, primaryID string, entries []unified.IndexEntry) (unified.UnifiedAdvisory, error) {
	var (
		refs        []unified.Reference
		descs       []descriptionItem
		sevs        []severityItem
		affs        []affectedItem
		provenances []unified.Provenance
	)
	sourceIDs := make(map[string]struct{})
	addSourceID := func(id string) {
		if id == "" || id == primaryID {
			return
		}
		sourceIDs[id] = struct{}{}
	}
	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return unified.UnifiedAdvisory{}, err
		}
		path := filepath.Join(sourcesRoot, e.Path)
		prov := unified.Provenance{Kind: e.Kind, Path: e.Path, ID: e.SourceID}
		provenances = append(provenances, prov)
		addSourceID(e.SourceID)
		switch e.Kind {
		case unified.SourceOSV:
			rec, err := readOSV(path, e.Source)
			if err != nil {
				return unified.UnifiedAdvisory{}, fmt.Errorf("%s: %w", e.Path, err)
			}
			base := rec.Base()
			source := SourceTag(e.Kind, e.Source)
			refs = append(refs, OSVReferences(base.References)...)
			descs = append(descs, OSVDescriptions(*base, prov, source)...)
			sevs = append(sevs, OSVSeverities(base.Severity, prov, source)...)
			affs = append(affs, OSVAffectedRecords(rec, prov, source)...)
			for _, a := range base.Aliases {
				addSourceID(a)
			}
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
		SourceIDs:    sortedSet(sourceIDs),
		Descriptions: mergeDescriptions(descs),
		References:   mergeReferences(refs),
		Severities:   mergeSeverities(sevs),
		Affected:     mergeAffected(affs),
		Provenances:  provenances,
	}, nil
}

// sortedSet returns the keys of a string set as a lex-sorted slice, or
// nil when empty so the JSON output preserves the omitempty semantics on
// optional alias bags.
func sortedSet(m map[string]struct{}) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// readOSV resolves the per-ecosystem typed parser via osv.Parse and
// returns the typed Record under the OSVRecord interface. ecoName is
// the on-disk ecosystem directory name as walker carved it out of the
// path (whitespace already replaced by `_`).
func readOSV(path, ecoName string) (osv.OSVRecord, error) {
	eco, err := osv.EcosystemFromString(ecoName)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ecosystem.Parse(eco, f)
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
