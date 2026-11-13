package annotator

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"

	"github.com/masahiro331/wisteria/internal/unified/vulncheckkev"
	"github.com/masahiro331/wisteria/pkg/advisory"
)

var vulncheckKEVCatalogRelPath = filepath.Join("vulncheck-kev", vulncheckkev.CatalogFilename)

// AnnotateVulnCheckKEV reads <sourcesRoot>/vulncheck-kev/<catalog> and, for
// every CVE with a matching unified file under <outDir>/cve/<year>/, sets
// UnifiedAdvisory.VulnCheckKEV and rewrites the file. The CISA KEV field is
// left as it is. Missing target → skip; missing catalog → no-op.
//
// A CVE is expected in one entry. If two entries name the same CVE, the one
// with the earlier date_added is attached and the duplicate is logged.
func AnnotateVulnCheckKEV(ctx context.Context, sourcesRoot, outDir string) error {
	catalogPath := filepath.Join(sourcesRoot, vulncheckKEVCatalogRelPath)
	f, err := os.Open(catalogPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("annotator: read %s: %w", catalogPath, err)
	}
	entries, err := vulncheckkev.Read(f)
	_ = f.Close()
	if err != nil {
		return fmt.Errorf("annotator: parse %s: %w", catalogPath, err)
	}
	byCVE := map[string]vulncheckkev.Entry{}
	for _, e := range entries {
		for _, id := range e.CVE {
			prev, dup := byCVE[id]
			if dup {
				slog.Warn("annotator: CVE in more than one VulnCheck KEV entry; keeping the earliest", "cve", id)
				if prev.DateAdded <= e.DateAdded {
					continue
				}
			}
			byCVE[id] = e
		}
	}
	ids := make([]string, 0, len(byCVE))
	for id := range byCVE {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			return err
		}
		rec := vulncheckKEVRecord(id, byCVE[id])
		if err := updateCVE(outDir, id, func(u *advisory.UnifiedAdvisory) { u.VulnCheckKEV = rec }); err != nil {
			return err
		}
	}
	return nil
}

// vulncheckKEVRecord copies one catalog entry into the unified shape.
func vulncheckKEVRecord(cveID string, e vulncheckkev.Entry) *advisory.VulnCheckKEVRecord {
	rec := &advisory.VulnCheckKEVRecord{
		From:                       advisory.Provenance{Kind: advisory.SourceVulnCheckKEV, Path: filepath.ToSlash(vulncheckKEVCatalogRelPath), ID: cveID},
		VendorProject:              e.VendorProject,
		Product:                    e.Product,
		ShortDescription:           e.ShortDescription,
		VulnerabilityName:          e.VulnerabilityName,
		RequiredAction:             e.RequiredAction,
		KnownRansomwareCampaignUse: e.KnownRansomwareCampaignUse,
		CWEs:                       e.CWEs,
		ReportedByCanaries:         e.ReportedByCanaries,
		DueDate:                    e.DueDate,
		CISADateAdded:              e.CISADateAdded,
		DateAdded:                  e.DateAdded,
		UpdatedAt:                  e.UpdatedAt,
		Timestamp:                  e.Timestamp,
	}
	for _, x := range e.XDB {
		rec.XDB = append(rec.XDB, advisory.VulnCheckXDB{ID: x.ID, URL: x.URL, DateAdded: x.DateAdded,
			ExploitType: x.ExploitType, CloneSSHURL: x.CloneSSHURL})
	}
	for _, r := range e.ReportedExploitation {
		rec.ReportedExploitation = append(rec.ReportedExploitation, advisory.VulnCheckReportedExploit{URL: r.URL, DateAdded: r.DateAdded})
	}
	return rec
}
