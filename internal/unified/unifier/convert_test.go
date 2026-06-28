package unifier

import (
	"testing"

	"github.com/masahiro331/wisteria/internal/unified"
	"github.com/masahiro331/wisteria/internal/unified/osv"
)

// TestOSVAffectedRecords_PreservesConcreteType checks that the
// ecosystem's concrete *AffectedX element survives into the
// AffectedRecord.OSV slot (no type erasure to a useless wrapper, no
// element-aliasing bug).
func TestOSVAffectedRecords_PreservesConcreteType(t *testing.T) {
	prov := unified.Provenance{Kind: unified.SourceOSV, Path: "osv/PyPI/x.json", ID: "PYSEC-1"}

	rec := &osv.RecordPyPI{
		Record: osv.Record{Ecosystem: osv.EcosystemPyPI, ID: "PYSEC-1"},
		Affected: []osv.AffectedPyPI{
			{AffectedBase: osv.AffectedBase{Package: &osv.Package{Name: "alpha", Ecosystem: "PyPI"}}},
			{AffectedBase: osv.AffectedBase{Package: &osv.Package{Name: "beta", Ecosystem: "PyPI"}}},
		},
	}

	got := OSVAffectedRecords(rec, prov, "osv.PyPI")
	if len(got) != 2 {
		t.Fatalf("len(got) = %d, want 2", len(got))
	}

	for i, name := range []string{"alpha", "beta"} {
		aff, ok := got[i].record.OSV.(*osv.AffectedPyPI)
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
	prov := unified.Provenance{Kind: unified.SourceOSV}
	rec := &osv.RecordPyPI{
		Affected: []osv.AffectedPyPI{
			{AffectedBase: osv.AffectedBase{Package: &osv.Package{Name: "a"}}},
			{AffectedBase: osv.AffectedBase{Package: &osv.Package{Name: "b"}}},
		},
	}
	got := OSVAffectedRecords(rec, prov, "osv.PyPI")
	p0 := got[0].record.OSV.(*osv.AffectedPyPI)
	p1 := got[1].record.OSV.(*osv.AffectedPyPI)
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
	prov := unified.Provenance{Kind: unified.SourceOSV}
	if got := OSVAffectedRecords(nil, prov, "osv.PyPI"); len(got) != 0 {
		t.Errorf("OSVAffectedRecords(nil) = %#v, want empty", got)
	}
}
