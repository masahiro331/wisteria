package unifier

import (
	"testing"

	"github.com/masahiro331/wisteria/internal/unified/osv"
	"github.com/masahiro331/wisteria/internal/unified/osv/ecosystem"
	"github.com/masahiro331/wisteria/pkg/advisory"
	"github.com/masahiro331/wisteria/pkg/advisory/cve"
)

// TestOSVAffectedRecords_PreservesConcreteType checks that the
// ecosystem's concrete *AffectedX element survives into the
// AffectedRecord.OSV slot (no type erasure to a useless wrapper, no
// element-aliasing bug).
func TestOSVAffectedRecords_PreservesConcreteType(t *testing.T) {
	prov := advisory.Provenance{Kind: advisory.SourceOSV, Path: "osv/PyPI/x.json", ID: "PYSEC-1"}

	rec := &ecosystem.RecordPyPI{
		Record: osv.Record{Ecosystem: osv.EcosystemPyPI, ID: "PYSEC-1"},
		Affected: []ecosystem.AffectedPyPI{
			{AffectedBase: osv.AffectedBase{Package: &osv.Package{Name: "alpha", Ecosystem: "PyPI"}}},
			{AffectedBase: osv.AffectedBase{Package: &osv.Package{Name: "beta", Ecosystem: "PyPI"}}},
		},
	}

	got := OSVAffectedRecords(rec, prov, "osv.PyPI")
	if len(got) != 2 {
		t.Fatalf("len(got) = %d, want 2", len(got))
	}

	for i, name := range []string{"alpha", "beta"} {
		aff, ok := got[i].record.OSV.(*ecosystem.AffectedPyPI)
		if !ok {
			t.Fatalf("got[%d].OSV type = %T, want *osv.AffectedPyPI", i, got[i].record.OSV)
		}
		if aff.Package == nil || aff.Package.Name != name {
			t.Errorf("got[%d] package = %#v, want name %q", i, aff.Package, name)
		}
	}
}

// TestOSVAffectedRecords_ElementsAreDistinct guards against the
// classic loop-variable aliasing bug: each yielded pointer must
// address its own copy, not a shared loop var.
func TestOSVAffectedRecords_ElementsAreDistinct(t *testing.T) {
	prov := advisory.Provenance{Kind: advisory.SourceOSV}
	rec := &ecosystem.RecordPyPI{
		Affected: []ecosystem.AffectedPyPI{
			{AffectedBase: osv.AffectedBase{Package: &osv.Package{Name: "a"}}},
			{AffectedBase: osv.AffectedBase{Package: &osv.Package{Name: "b"}}},
		},
	}
	got := OSVAffectedRecords(rec, prov, "osv.PyPI")
	p0 := got[0].record.OSV.(*ecosystem.AffectedPyPI)
	p1 := got[1].record.OSV.(*ecosystem.AffectedPyPI)
	if p0 == p1 {
		t.Fatal("both elements share the same pointer (loop-variable aliasing)")
	}
	if p0.Package.Name != "a" || p1.Package.Name != "b" {
		t.Errorf("aliasing corrupted values: p0=%q p1=%q", p0.Package.Name, p1.Package.Name)
	}
}

// TestOSVAffectedRecords_NilRecord guards the nil-record path: no
// panic and no spurious items.
func TestOSVAffectedRecords_NilRecord(t *testing.T) {
	prov := advisory.Provenance{Kind: advisory.SourceOSV}
	if got := OSVAffectedRecords(nil, prov, "osv.PyPI"); len(got) != 0 {
		t.Errorf("OSVAffectedRecords(nil) = %#v, want empty", got)
	}
}

// TestOSVDescriptions_RolesAndLang pins the role marker that makes OSV's
// two unmarked entries distinguishable, and the BCP47 primary-subtag
// lang normalization shared with CVEDescriptions.
func TestOSVDescriptions_RolesAndLang(t *testing.T) {
	prov := advisory.Provenance{Kind: advisory.SourceOSV, Path: "osv/PyPI/PYSEC-1.json", ID: "PYSEC-1"}
	rec := osv.Record{Summary: "short", Details: "long text"}

	got := OSVDescriptions(rec, prov, "osv.PyPI")

	if len(got) != 2 {
		t.Fatalf("got %d items, want 2", len(got))
	}
	if got[0].Role != advisory.DescriptionSummary || got[0].Text != "short" || got[0].Lang != "en" {
		t.Errorf("summary item = %+v", got[0].Description)
	}
	if got[1].Role != advisory.DescriptionDetails || got[1].Text != "long text" {
		t.Errorf("details item = %+v", got[1].Description)
	}
}

func TestCVEDescriptions_RoleAndLangNormalization(t *testing.T) {
	prov := advisory.Provenance{Kind: advisory.SourceCVE, Path: "cve/x.json", ID: "CVE-2024-0001"}
	in := []cve.Description{
		{Lang: "en-US", Value: "english text"},
		{Lang: "de", Value: "deutscher Text"},
	}

	got := CVEDescriptions(in, prov)

	if len(got) != 2 {
		t.Fatalf("got %d items, want 2", len(got))
	}
	if got[0].Lang != "en" {
		t.Errorf("lang en-US not normalized: %q", got[0].Lang)
	}
	if got[0].Role != advisory.DescriptionDetails || got[1].Role != advisory.DescriptionDetails {
		t.Errorf("CVE roles = %q / %q, want details", got[0].Role, got[1].Role)
	}
	if got[1].Lang != "de" {
		t.Errorf("lang de = %q", got[1].Lang)
	}
}
