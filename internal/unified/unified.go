// Package unified defines the core types of the unified-advisory pipeline:
// the source-kind enum, provenance + index entries used by Stage 1 (walker),
// the merged-leaf types used by Stage 2 (unifier), the KEV / EPSS signal
// types used by Stage 4 (annotator), and the UnifiedAdvisory itself which
// is what Stage 3 (writer) emits to disk.
//
// Per-source raw schemas live in sibling subpackages (osv, cve, kev, epss).
// This file intentionally has no behavior — only types — so every stage
// package can depend on it without picking up unrelated transitive deps.
package unified

import (
	"github.com/masahiro331/wisteria/internal/unified/cve"
	"github.com/masahiro331/wisteria/internal/unified/osv"
)

// SourceKind identifies which upstream catalog a record came from.
type SourceKind string

const (
	SourceOSV  SourceKind = "osv"
	SourceCVE  SourceKind = "cve"
	SourceKEV  SourceKind = "kev"
	SourceEPSS SourceKind = "epss"
)

// Provenance is the "where did this come from" trail attached to every
// merged leaf. The raw bytes live under <cache-dir>/sources/, so we only
// keep the relative path and the original record id, not the body.
type Provenance struct {
	Kind SourceKind `json:"kind"`
	Path string     `json:"path"`
	ID   string     `json:"id"`
}

// IndexEntry is one row of Stage 1's output: enough to re-open the file
// in Stage 2 (AbsPath), enough to record Provenance (RelPath + SourceID),
// and enough to route writes in Stage 3 (Kind + Source).
type IndexEntry struct {
	AbsPath  string
	RelPath  string
	Kind     SourceKind
	Source   string
	SourceID string
}

// Reference is one merged external link. Tags unions OSV's `type` and
// CVE5's `tags` — same URL across sources collapses, tags dedup.
type Reference struct {
	URL  string   `json:"url"`
	Tags []string `json:"tags,omitempty"`
}

// Description is one description text from one source. We do not merge
// descriptions across sources — each is kept as-is with its provenance,
// because phrasing matters and Phase 2 (AI) decides which to surface.
type Description struct {
	Lang string     `json:"lang"`
	Text string     `json:"text"`
	From Provenance `json:"from"`
}

// Severity is one CVSS-style score. Same-vector duplicates from different
// sources collapse; differing assessments are kept side by side.
type Severity struct {
	Type   string     `json:"type"`
	Score  string     `json:"score,omitempty"`
	Vector string     `json:"vector,omitempty"`
	From   Provenance `json:"from"`
}

// AffectedRecord is one source's affected-package block, kept verbatim.
// We do not try to reconcile OSV ranges against CVE5 platform/version
// shapes here — the typed source struct is preserved so downstream stages
// (Phase 2 / Phase 3) can decide.
type AffectedRecord struct {
	From Provenance    `json:"from"`
	OSV  *osv.Affected `json:"osv,omitempty"`
	CVE  *cve.Affected `json:"cve,omitempty"`
}

// EPSSScore is the FIRST EPSS daily score for one CVE-ID. Stage 4 attaches
// it to an existing UnifiedAdvisory; the EPSS catalog is unique by CVE-ID.
type EPSSScore struct {
	From         Provenance `json:"from"`
	Score        float64    `json:"score"`
	Percentile   float64    `json:"percentile"`
	ScoreDate    string     `json:"score_date"`
	ModelVersion string     `json:"model_version,omitempty"`
}

// KEVRecord is one CISA KEV catalog entry. Stage 4 attaches it to an
// existing UnifiedAdvisory; KEV is unique by CVE-ID.
type KEVRecord struct {
	From                       Provenance `json:"from"`
	VendorProject              string     `json:"vendor_project,omitempty"`
	Product                    string     `json:"product,omitempty"`
	VulnerabilityName          string     `json:"vulnerability_name,omitempty"`
	DateAdded                  string     `json:"date_added,omitempty"`
	ShortDescription           string     `json:"short_description,omitempty"`
	RequiredAction             string     `json:"required_action,omitempty"`
	DueDate                    string     `json:"due_date,omitempty"`
	KnownRansomwareCampaignUse string     `json:"known_ransomware_campaign_use,omitempty"`
	Notes                      string     `json:"notes,omitempty"`
	CWEs                       []string   `json:"cwes,omitempty"`
}

// UnifiedAdvisory is the merged record keyed by PrimaryID. SourceIDs holds
// every other identifier the same vuln is known by (dedup + sorted), so a
// caller searching by GHSA / PYSEC / ALBA still finds the CVE-keyed file.
type UnifiedAdvisory struct {
	PrimaryID    string           `json:"primary_id"`
	SourceIDs    []string         `json:"source_ids,omitempty"`
	Descriptions []Description    `json:"descriptions"`
	References   []Reference      `json:"references"`
	Severities   []Severity       `json:"severities"`
	Affected     []AffectedRecord `json:"affected"`
	KEV          *KEVRecord       `json:"kev,omitempty"`
	EPSS         *EPSSScore       `json:"epss,omitempty"`
	Provenances  []Provenance     `json:"provenances"`
}
