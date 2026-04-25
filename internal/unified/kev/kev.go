// Package kev defines parser types for the CISA Known Exploited
// Vulnerabilities catalog. Field names follow the upstream JSON; only the
// fields wisteria's pipeline reads are declared.
package kev

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Catalog mirrors the top-level KEV JSON document.
type Catalog struct {
	Title           string          `json:"title"`
	CatalogVersion  string          `json:"catalogVersion"`
	DateReleased    time.Time       `json:"dateReleased"`
	Count           int             `json:"count"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

// Vulnerability is one KEV entry.
type Vulnerability struct {
	CVEID                      string   `json:"cveID"`
	VendorProject              string   `json:"vendorProject"`
	Product                    string   `json:"product"`
	VulnerabilityName          string   `json:"vulnerabilityName"`
	DateAdded                  Date     `json:"dateAdded"`
	ShortDescription           string   `json:"shortDescription"`
	RequiredAction             string   `json:"requiredAction"`
	DueDate                    Date     `json:"dueDate"`
	KnownRansomwareCampaignUse string   `json:"knownRansomwareCampaignUse"`
	Notes                      string   `json:"notes"`
	CWEs                       []string `json:"cwes"`
}

// Date wraps time.Time so KEV's "YYYY-MM-DD" date strings unmarshal cleanly.
// An absent or empty value leaves the underlying time.Time zero.
type Date struct {
	time.Time
}

const dateLayout = "2006-01-02"

// UnmarshalJSON parses a "YYYY-MM-DD" string into Date. JSON null and an
// empty string both yield the zero value.
func (d *Date) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		d.Time = time.Time{}
		return nil
	}
	t, err := time.Parse(dateLayout, s)
	if err != nil {
		return fmt.Errorf("kev date %q: %w", s, err)
	}
	d.Time = t
	return nil
}

// MarshalJSON emits "YYYY-MM-DD"; the zero value emits null so round-tripping
// an absent field stays absent.
func (d Date) MarshalJSON() ([]byte, error) {
	if d.IsZero() {
		return []byte("null"), nil
	}
	return json.Marshal(d.Format(dateLayout))
}
