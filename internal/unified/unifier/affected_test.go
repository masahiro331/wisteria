package unifier

import (
	"reflect"
	"testing"

	"github.com/masahiro331/wisteria/internal/unified"
	"github.com/masahiro331/wisteria/internal/unified/cve"
	"github.com/masahiro331/wisteria/internal/unified/osv"
)

func TestMergeAffected(t *testing.T) {
	provCVE := unified.Provenance{Kind: unified.SourceCVE, Path: "cve/x.json", ID: "CVE-2024-0001"}
	provAlma := unified.Provenance{Kind: unified.SourceOSV, Path: "osv/AlmaLinux/ALSA-1.json", ID: "ALSA-1"}
	provGit := unified.Provenance{Kind: unified.SourceOSV, Path: "osv/GitHub Reviewed/GHSA-1.json", ID: "GHSA-1"}

	osvAff := func(name string) *osv.Affected {
		return &osv.Affected{Package: &osv.Package{Name: name, Ecosystem: "PyPI"}}
	}
	cveAff := func(product string) *cve.Affected {
		return &cve.Affected{Vendor: "acme", Product: product}
	}

	tests := []struct {
		name string
		in   []affectedItem
		want []unified.AffectedRecord
	}{
		{
			name: "empty input returns nil",
			in:   nil,
			want: nil,
		},
		{
			name: "single OSV affected passes through with OSV substructure",
			in: []affectedItem{
				{record: unified.AffectedRecord{From: provAlma, OSV: osvAff("pkgA")}, source: "osv.AlmaLinux"},
			},
			want: []unified.AffectedRecord{
				{From: provAlma, OSV: osvAff("pkgA")},
			},
		},
		{
			// §8.5 sort: priority array → Provenance.ID → input index.
			name: "sort by source priority then Provenance.ID then input index",
			in: []affectedItem{
				{record: unified.AffectedRecord{From: provGit, OSV: osvAff("z")}, source: "osv.GitHub_Reviewed"},
				{record: unified.AffectedRecord{From: provCVE, CVE: cveAff("p1")}, source: "cve.mitre"},
				{record: unified.AffectedRecord{From: provAlma, OSV: osvAff("a")}, source: "osv.AlmaLinux"},
				{record: unified.AffectedRecord{From: provAlma, OSV: osvAff("b")}, source: "osv.AlmaLinux"},
			},
			want: []unified.AffectedRecord{
				{From: provCVE, CVE: cveAff("p1")},
				{From: provAlma, OSV: osvAff("a")},
				{From: provAlma, OSV: osvAff("b")},
				{From: provGit, OSV: osvAff("z")},
			},
		},
		{
			// CNA + ADP both retained; same source tag (cve.mitre) but
			// distinct Provenance.ID. Sort by ID puts CNA before ADP
			// because the latter uses an "#adp:" suffix.
			name: "CVE CNA and ADP both retained, sorted by Provenance.ID",
			in: []affectedItem{
				{record: unified.AffectedRecord{
					From: unified.Provenance{Kind: unified.SourceCVE, Path: provCVE.Path, ID: "CVE-2024-0001#adp:cisa"},
					CVE:  cveAff("adp"),
				}, source: "cve.mitre"},
				{record: unified.AffectedRecord{From: provCVE, CVE: cveAff("cna")}, source: "cve.mitre"},
			},
			want: []unified.AffectedRecord{
				{From: provCVE, CVE: cveAff("cna")},
				{From: unified.Provenance{Kind: unified.SourceCVE, Path: provCVE.Path, ID: "CVE-2024-0001#adp:cisa"}, CVE: cveAff("adp")},
			},
		},
		{
			// Same Provenance.ID with multiple Affected entries (1 OSV
			// file ships N packages): keep input order via index
			// tie-break so output is reproducible.
			name: "same Provenance.ID falls back to input index",
			in: []affectedItem{
				{record: unified.AffectedRecord{From: provAlma, OSV: osvAff("first")}, source: "osv.AlmaLinux"},
				{record: unified.AffectedRecord{From: provAlma, OSV: osvAff("second")}, source: "osv.AlmaLinux"},
				{record: unified.AffectedRecord{From: provAlma, OSV: osvAff("third")}, source: "osv.AlmaLinux"},
			},
			want: []unified.AffectedRecord{
				{From: provAlma, OSV: osvAff("first")},
				{From: provAlma, OSV: osvAff("second")},
				{From: provAlma, OSV: osvAff("third")},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := mergeAffected(tc.in)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("mergeAffected\n got = %#v\nwant = %#v", got, tc.want)
			}
		})
	}
}
