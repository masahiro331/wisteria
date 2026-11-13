// Package vulncheckkev defines parser types for the VulnCheck KEV catalog
// (VulnCheck Known Exploited Vulnerabilities, https://vulncheck.com/kev).
// The catalog is the JSON array inside the backup the VulnCheck API hands
// out; field names follow it verbatim and every field is declared, so a
// parse + re-marshal round trip keeps all keys. Dates stay as the upstream
// RFC 3339 strings.
package vulncheckkev

import (
	"encoding/json"
	"fmt"
	"io"
)

// CatalogFilename is the catalog's name inside the backup zip, kept as the
// on-disk name under <cache-dir>/sources/vulncheck-kev/.
const CatalogFilename = "vulncheck_known_exploited_vulnerabilities.json"

// Entry is one VulnCheck KEV record. CVE is an array upstream; every record
// seen so far carries exactly one.
type Entry struct {
	VendorProject              string            `json:"vendorProject"`
	Product                    string            `json:"product"`
	ShortDescription           string            `json:"shortDescription"`
	VulnerabilityName          string            `json:"vulnerabilityName"`
	RequiredAction             string            `json:"required_action"`
	KnownRansomwareCampaignUse string            `json:"knownRansomwareCampaignUse"`
	CVE                        []string          `json:"cve"`
	CWEs                       []string          `json:"cwes"`
	XDB                        []XDB             `json:"vulncheck_xdb"`
	ReportedExploitation       []ReportedExploit `json:"vulncheck_reported_exploitation"`
	ReportedByCanaries         bool              `json:"reported_exploited_by_vulncheck_canaries"`
	// DueDate and CISADateAdded are present only for entries also in CISA KEV.
	DueDate       string `json:"dueDate,omitempty"`
	CISADateAdded string `json:"cisa_date_added,omitempty"`
	DateAdded     string `json:"date_added"`
	// UpdatedAt is in the data though not in VulnCheck's documented schema.
	UpdatedAt string `json:"updated_at"`
	Timestamp string `json:"_timestamp"`
}

// XDB is one exploit VulnCheck XDB lists for the CVE.
type XDB struct {
	ID          string `json:"xdb_id"`
	URL         string `json:"xdb_url"`
	DateAdded   string `json:"date_added"`
	ExploitType string `json:"exploit_type"`
	CloneSSHURL string `json:"clone_ssh_url"`
}

// ReportedExploit is one citation for the CVE being exploited in the wild.
type ReportedExploit struct {
	URL       string `json:"url"`
	DateAdded string `json:"date_added"`
}

// Read parses the catalog: a JSON array of entries.
func Read(r io.Reader) ([]Entry, error) {
	var entries []Entry
	if err := json.NewDecoder(r).Decode(&entries); err != nil {
		return nil, fmt.Errorf("vulncheckkev: parse catalog: %w", err)
	}
	return entries, nil
}
