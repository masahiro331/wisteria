package unifier

import (
	"reflect"
	"strings"
	"testing"

	"github.com/masahiro331/wisteria/internal/unified/osv"
	"github.com/masahiro331/wisteria/internal/unified/osv/ecosystem"
	"github.com/masahiro331/wisteria/pkg/advisory"
	"github.com/masahiro331/wisteria/pkg/advisory/cve"
)

// Official MITRE names the tests below expect the merge to attach.
const (
	cweXSS  = "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"
	cweSQLI = "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"
)

func TestMergeWeaknesses(t *testing.T) {
	provCVE := advisory.Provenance{Kind: advisory.SourceCVE, Path: "cve/x.json", ID: "CVE-2024-0001"}
	provPyPI := advisory.Provenance{Kind: advisory.SourceOSV, Path: "osv/PyPI/PYSEC-1.json", ID: "PYSEC-1"}

	tests := []struct {
		name    string
		in      []advisory.Weakness
		sources []string // source tag of each in[i] (parallel slice)
		want    []advisory.Weakness
	}{
		{
			name: "same CWE-ID collapses keeping the higher-priority source",
			in: []advisory.Weakness{
				{CWEID: "CWE-79", From: provPyPI},
				{CWEID: "CWE-79", From: provCVE},
			},
			sources: []string{"osv.PyPI", SourceCVEMitre},
			want: []advisory.Weakness{
				{CWEID: "CWE-79", Name: cweXSS, From: provCVE},
			},
		},
		{
			name: "distinct CWE-IDs are kept and ordered by priority then id",
			in: []advisory.Weakness{
				{CWEID: "CWE-89", From: provPyPI},
				{CWEID: "CWE-79", From: provCVE},
				{CWEID: "CWE-20", From: provPyPI},
			},
			sources: []string{"osv.PyPI", SourceCVEMitre, "osv.PyPI"},
			want: []advisory.Weakness{
				{CWEID: "CWE-79", Name: cweXSS, From: provCVE},
				{CWEID: "CWE-20", Name: "Improper Input Validation", From: provPyPI},
				{CWEID: "CWE-89", Name: cweSQLI, From: provPyPI},
			},
		},
		{
			name: "unknown CWE-ID keeps an empty name",
			in: []advisory.Weakness{
				{CWEID: "CWE-999999", From: provCVE},
			},
			sources: []string{SourceCVEMitre},
			want: []advisory.Weakness{
				{CWEID: "CWE-999999", From: provCVE},
			},
		},
		{
			name: "empty input returns nil",
			in:   nil,
			want: nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			items := make([]weaknessItem, len(tc.in))
			for i, w := range tc.in {
				items[i] = weaknessItem{Weakness: w, source: tc.sources[i]}
			}
			got := mergeWeaknesses(items)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("mergeWeaknesses = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestCVEWeaknesses_ExtractsCWEIDEntriesOnly(t *testing.T) {
	prov := advisory.Provenance{Kind: advisory.SourceCVE, Path: "cve/x.json", ID: "CVE-2024-0001"}
	in := []cve.ProblemType{
		{Descriptions: []cve.ProblemDescription{
			{Type: "CWE", Lang: "en", CWEID: "CWE-79", Description: "Cross-site Scripting"},
			{Type: "text", Lang: "en", Description: "no cwe id here"},
		}},
		{Descriptions: []cve.ProblemDescription{
			{Type: "CWE", Lang: "en", CWEID: "CWE-89", Description: "SQL Injection"},
		}},
	}

	got := CVEWeaknesses(in, prov)

	want := []weaknessItem{
		{Weakness: advisory.Weakness{CWEID: "CWE-79", From: prov}, source: SourceCVEMitre},
		{Weakness: advisory.Weakness{CWEID: "CWE-89", From: prov}, source: SourceCVEMitre},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("CVEWeaknesses = %+v, want %+v", got, want)
	}
}

func TestOSVWeaknesses_ReadsRecordCWEIDs(t *testing.T) {
	prov := advisory.Provenance{Kind: advisory.SourceOSV, Path: "osv/PyPI/PYSEC-1.json", ID: "PYSEC-1"}
	rec, err := ecosystem.Parse(osv.EcosystemPyPI, strings.NewReader(
		`{"id":"PYSEC-1","database_specific":{"cwe_ids":["CWE-78","CWE-20"]}}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	got := OSVWeaknesses(rec, prov, "osv.PyPI")

	want := []weaknessItem{
		{Weakness: advisory.Weakness{CWEID: "CWE-78", From: prov}, source: "osv.PyPI"},
		{Weakness: advisory.Weakness{CWEID: "CWE-20", From: prov}, source: "osv.PyPI"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("OSVWeaknesses = %+v, want %+v", got, want)
	}
}

func TestOSVWeaknesses_RecordWithoutCWEsIsEmpty(t *testing.T) {
	prov := advisory.Provenance{Kind: advisory.SourceOSV, Path: "osv/AlmaLinux/ALSA-1.json", ID: "ALSA-1"}
	rec, err := ecosystem.Parse(osv.EcosystemAlmaLinux, strings.NewReader(`{"id":"ALSA-1"}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := OSVWeaknesses(rec, prov, "osv.AlmaLinux"); len(got) != 0 {
		t.Errorf("OSVWeaknesses = %+v, want empty", got)
	}
	if got := OSVWeaknesses(nil, prov, "osv.AlmaLinux"); got != nil {
		t.Errorf("OSVWeaknesses(nil) = %+v, want nil", got)
	}
}
