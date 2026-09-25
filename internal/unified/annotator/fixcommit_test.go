package annotator

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/masahiro331/wisteria/pkg/advisory"
)

func TestDeriveFixCommits_FromOSVAndReferences(t *testing.T) {
	rec := &advisory.UnifiedAdvisory{
		References: []advisory.Reference{
			{URL: "https://github.com/o/r/commit/f290be6b2abef4a382bb84c4feeea0fa76b8d012"},
			{URL: "https://github.com/o/r/security/advisories/GHSA-x"}, // ignored
		},
		Affected: []advisory.AffectedRecord{
			{OSV: map[string]any{"ranges": []any{
				map[string]any{"type": "GIT", "repo": "https://github.com/lib/pkg",
					"events": []any{map[string]any{"introduced": "0"}, map[string]any{"fixed": "ABC1234"}}},
			}}},
		},
	}
	got := DeriveFixCommits(rec)
	if len(got) != 2 {
		t.Fatalf("want 2 fix commits, got %d: %+v", len(got), got)
	}
	// OSV first, then reference.
	if got[0].Repo != "lib/pkg" || got[0].SHA != "abc1234" || got[0].From.Kind != advisory.SourceOSV {
		t.Errorf("osv-derived wrong: %+v", got[0])
	}
	if got[1].Repo != "o/r" || got[1].SHA != "f290be6b2abef4a382bb84c4feeea0fa76b8d012" {
		t.Errorf("reference-derived wrong: %+v", got[1])
	}
	if got[1].URL == "" {
		t.Error("reference fix commit should keep its URL")
	}
}

func TestDeriveFixCommits_DedupesSameRepoSHA(t *testing.T) {
	rec := &advisory.UnifiedAdvisory{
		References: []advisory.Reference{{URL: "https://github.com/o/r/commit/aaaaaaa"}},
		Affected: []advisory.AffectedRecord{
			{OSV: map[string]any{"ranges": []any{
				map[string]any{"type": "GIT", "repo": "https://github.com/o/r",
					"events": []any{map[string]any{"fixed": "AAAAAAA"}}},
			}}},
		},
	}
	if got := DeriveFixCommits(rec); len(got) != 1 {
		t.Errorf("same repo@sha from two sources must dedupe to 1, got %d: %+v", len(got), got)
	}
}

func TestDeriveFixCommits_NoneWhenNoCommit(t *testing.T) {
	rec := &advisory.UnifiedAdvisory{
		References: []advisory.Reference{{URL: "https://nvd.nist.gov/vuln/detail/CVE-x"}},
	}
	if got := DeriveFixCommits(rec); len(got) != 0 {
		t.Errorf("no commit sources must yield none, got %+v", got)
	}
}

func TestAnnotateFixCommits_WritesField(t *testing.T) {
	out := t.TempDir()
	dir := filepath.Join(out, "cve", "2026")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	rec := advisory.UnifiedAdvisory{
		PrimaryID:  "CVE-2026-0001",
		References: []advisory.Reference{{URL: "https://github.com/o/r/commit/deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}},
	}
	body, _ := json.MarshalIndent(rec, "", "  ")
	path := filepath.Join(dir, "CVE-2026-0001.json")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := AnnotateFixCommits(context.Background(), "", out); err != nil {
		t.Fatal(err)
	}

	got, ok, err := readUnified(path)
	if err != nil || !ok {
		t.Fatalf("reread: ok=%v err=%v", ok, err)
	}
	if len(got.FixCommits) != 1 || got.FixCommits[0].SHA != "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef" {
		t.Errorf("fix commit not written: %+v", got.FixCommits)
	}
}

func TestAnnotateFixCommits_MissingTreeIsNoOp(t *testing.T) {
	if err := AnnotateFixCommits(context.Background(), "", t.TempDir()); err != nil {
		t.Errorf("missing cve/ tree must be a no-op, got %v", err)
	}
}
