// Package advisory defines the public core types of a built Wisteria
// database: the source-kind enum, the provenance trail attached to every
// merged leaf, the merged-leaf types themselves, the KEV / EPSS /
// Exploit-DB signal types, and the UnifiedAdvisory record that the
// pipeline emits and pkg/db drivers return.
//
// The CVE5 raw schema that UnifiedAdvisory embeds lives in the cve
// subpackage. This package intentionally has no behavior — only
// types — so both the internal pipeline stages and external consumers
// can depend on it without picking up unrelated transitive deps.
package advisory

import (
	"time"

	"github.com/masahiro331/wisteria/pkg/advisory/cve"
)

// SourceKind identifies which upstream catalog a record came from.
type SourceKind string

const (
	SourceOSV       SourceKind = "osv"
	SourceCVE       SourceKind = "cve"
	SourceKEV       SourceKind = "kev"
	SourceEPSS      SourceKind = "epss"
	SourceExploitDB SourceKind = "exploitdb"
)

// Provenance is the "where did this come from" trail attached to every
// merged leaf. The raw bytes live under <cache-dir>/sources/, so we only
// keep the relative path and the original record id, not the body.
type Provenance struct {
	Kind SourceKind `json:"kind"`
	Path string     `json:"path"`
	ID   string     `json:"id"`
}

// Reference is one merged external link. Tags unions OSV's `type` and
// CVE5's `tags` — same URL across sources collapses, tags dedup.
type Reference struct {
	URL  string   `json:"url"`
	Tags []string `json:"tags,omitempty"`
}

// Description role values. The role describes the text's function, not
// its source: OSV's one-line summary is a "summary"; OSV details and
// CVE5 description texts are both "details", so consumers pick by
// function without knowing which catalog contributed the entry.
const (
	DescriptionSummary = "summary"
	DescriptionDetails = "details"
)

// Description is one description text from one source. We do not merge
// descriptions across sources — each is kept as-is with its provenance,
// because phrasing matters and Phase 2 (AI) decides which to surface.
// Lang is normalized to the BCP47 primary subtag ("en-US" → "en").
type Description struct {
	Role string     `json:"role"`
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

// Weakness is one CWE assignment. Same CWE-ID across sources collapses
// (highest-priority source wins). Name is the official MITRE catalog
// title, attached uniformly at merge time regardless of which source
// asserted the CWE — per-source free text is intentionally not kept, so
// the unified shape does not vary by source. Name is empty only when
// the identifier is unknown to the embedded catalog (malformed CNA
// placeholders like "n/a", or IDs newer than the catalog generation).
type Weakness struct {
	CWEID string     `json:"cwe_id"`
	Name  string     `json:"name,omitempty"`
	From  Provenance `json:"from"`
}

// AffectedRecord is one source's affected-package block, kept verbatim.
// We do not try to reconcile OSV ranges against CVE5 platform/version
// shapes here — the typed source struct is preserved so downstream stages
// (Phase 2 / Phase 3) can decide.
//
// OSV is `any` because each ecosystem has its own concrete `osv.AffectedX`
// type; downstream consumers type-switch on the wrapping `Provenance`'s
// Source to recover the concrete shape.
type AffectedRecord struct {
	From Provenance    `json:"from"`
	OSV  any           `json:"osv,omitempty"`
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

// ExploitDBRecord is one row of the Exploit-DB files_exploits.csv catalog.
// Stage 4 attaches one or more of these to an existing UnifiedAdvisory:
// a single CVE-ID can have multiple EDB-IDs (different platforms,
// different researchers), so UnifiedAdvisory.Exploits is a slice and
// the catalog's natural row order is preserved.
type ExploitDBRecord struct {
	From          Provenance `json:"from"`
	ID            int        `json:"id"`             // EDB-ID
	URL           string     `json:"url"`            // https://www.exploit-db.com/exploits/<id>
	Title         string     `json:"title"`          // CSV "description"
	DatePublished string     `json:"date_published"` // YYYY-MM-DD
	Type          string     `json:"type,omitempty"`
	Platform      string     `json:"platform,omitempty"`
	Verified      bool       `json:"verified"`
}

// UnifiedAdvisory is the merged record keyed by PrimaryID. SourceIDs holds
// every other identifier the same vuln is known by (dedup + sorted), so a
// caller searching by GHSA / PYSEC / ALBA still finds the CVE-keyed file.
//
// Published is the earliest time any source published the advisory;
// Modified is the latest time any source touched it. Zero (absent in
// JSON) when no source carried the respective date.
type UnifiedAdvisory struct {
	PrimaryID    string            `json:"primary_id"`
	SourceIDs    []string          `json:"source_ids,omitempty"`
	Published    time.Time         `json:"published,omitzero"`
	Modified     time.Time         `json:"modified,omitzero"`
	Descriptions []Description     `json:"descriptions"`
	References   []Reference       `json:"references"`
	Severities   []Severity        `json:"severities"`
	Weaknesses   []Weakness        `json:"weaknesses,omitempty"`
	Affected     []AffectedRecord  `json:"affected"`
	KEV          *KEVRecord        `json:"kev,omitempty"`
	EPSS         *EPSSScore        `json:"epss,omitempty"`
	Exploits     []ExploitDBRecord `json:"exploits,omitempty"`
	Provenances  []Provenance      `json:"provenances"`
}
