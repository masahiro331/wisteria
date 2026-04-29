package osv

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// TestNewRecordPyPI_Fields confirms the embedded `Record` plus
// PyPI-specific fields land in the typed struct.
func TestNewRecordPyPI_Fields(t *testing.T) {
	const body = `{
		"id": "PYSEC-2021-872",
		"aliases": ["CVE-2021-42343", "GHSA-hwqr-f3v9-hwxr"],
		"summary": "Dask remote code execution.",
		"details": "Dask 2021.10.0 and earlier ...",
		"references": [
			{"type": "ADVISORY", "url": "https://example/a"},
			{"type": "FIX", "url": "https://example/b"}
		],
		"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N"}],
		"affected": [{
			"package": {"ecosystem": "PyPI", "name": "dask", "purl": "pkg:pypi/dask"},
			"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2021.10.0"}]}],
			"versions": ["2021.9.1", "2021.9.0"],
			"database_specific": {"source": "https://example/x.json"}
		}],
		"database_specific": {"cwe_ids": ["CWE-78"], "github_reviewed": true, "severity": "HIGH"}
	}`
	got, err := NewRecordPyPI(strings.NewReader(body))
	if err != nil {
		t.Fatalf("NewRecordPyPI: %v", err)
	}
	if got.Ecosystem != EcosystemPyPI {
		t.Errorf("Ecosystem = %v, want %v", got.Ecosystem, EcosystemPyPI)
	}
	if got.ID != "PYSEC-2021-872" {
		t.Errorf("ID = %q", got.ID)
	}
	if len(got.Affected) != 1 {
		t.Fatalf("Affected len = %d", len(got.Affected))
	}
	a := got.Affected[0]
	if a.Package == nil || a.Package.Name != "dask" {
		t.Errorf("Package = %#v", a.Package)
	}
	if a.DatabaseSpecific.Source != "https://example/x.json" {
		t.Errorf("aff db.Source = %q", a.DatabaseSpecific.Source)
	}
	if got.DatabaseSpecific.Severity != "HIGH" || !got.DatabaseSpecific.GitHubReviewed {
		t.Errorf("Top = %#v", got.DatabaseSpecific)
	}
	if len(got.DatabaseSpecific.CWEIDs) != 1 || got.DatabaseSpecific.CWEIDs[0] != "CWE-78" {
		t.Errorf("CWEIDs = %v", got.DatabaseSpecific.CWEIDs)
	}
}

// TestNewRecordPyPI_FullTopMetadata covers schema_version / published
// / withdrawn / credits etc. against the embedded Record fields.
func TestNewRecordPyPI_FullTopMetadata(t *testing.T) {
	const body = `{
		"schema_version": "1.7.3",
		"id": "GHSA-xyz",
		"published": "2009-11-20T18:30:00.327Z",
		"modified": "2025-11-19T05:57:42.162407Z",
		"withdrawn": "2025-11-20T00:00:00Z",
		"upstream": ["CVE-2009-3895"],
		"credits": [{"name": "Checkmarx", "contact": ["a@b"], "type": "FINDER"}],
		"database_specific": {"severity": "CRITICAL", "github_reviewed": true}
	}`
	got, err := NewRecordPyPI(strings.NewReader(body))
	if err != nil {
		t.Fatalf("NewRecordPyPI: %v", err)
	}
	if got.SchemaVersion != "1.7.3" {
		t.Errorf("SchemaVersion = %q", got.SchemaVersion)
	}
	wantPub := time.Date(2009, 11, 20, 18, 30, 0, 327000000, time.UTC)
	if !got.Published.Equal(wantPub) {
		t.Errorf("Published = %s, want %s", got.Published, wantPub)
	}
	if got.Withdrawn.IsZero() {
		t.Errorf("Withdrawn should be set")
	}
	if len(got.Credits) != 1 || got.Credits[0].Name != "Checkmarx" {
		t.Errorf("Credits = %#v", got.Credits)
	}
}

// TestParse_DispatchesByEcosystem confirms the dynamic Parse entry
// returns the right concrete type. The dispatch table is exhaustive,
// so type-asserting after Parse is a 1-line operation at the call
// site.
func TestParse_DispatchesByEcosystem(t *testing.T) {
	const body = `{"id": "X-1"}`
	rec, err := Parse(EcosystemPyPI, strings.NewReader(body))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, ok := rec.(*RecordPyPI); !ok {
		t.Fatalf("Parse returned %T, want *RecordPyPI", rec)
	}
	if rec.Base().ID != "X-1" {
		t.Errorf("ID via Base() = %q", rec.Base().ID)
	}
	if rec.Base().Ecosystem != EcosystemPyPI {
		t.Errorf("Ecosystem via Base() = %v", rec.Base().Ecosystem)
	}
}

// TestParse_UnknownEcosystem — Ecosystem values outside the constant
// block must hard-error; the dispatch table is closed.
func TestParse_UnknownEcosystem(t *testing.T) {
	if _, err := Parse(Ecosystem(9999), strings.NewReader(`{}`)); err == nil {
		t.Fatal("Parse must error on unknown Ecosystem")
	}
}

// TestEcosystemFromString covers verbatim and space-normalized forms.
func TestEcosystemFromString(t *testing.T) {
	cases := []struct {
		in   string
		want Ecosystem
	}{
		{"PyPI", EcosystemPyPI},
		{"Red Hat", EcosystemRedHat},
		{"Red_Hat", EcosystemRedHat}, // walker uses the underscore form
		{"crates.io", EcosystemCratesIO},
	}
	for _, tc := range cases {
		got, err := EcosystemFromString(tc.in)
		if err != nil {
			t.Errorf("EcosystemFromString(%q): %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("EcosystemFromString(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
	if _, err := EcosystemFromString("Unknown"); err == nil {
		t.Error("EcosystemFromString must error on unknown name")
	}
}

// TestRoundTrip_PyPI confirms parse → marshal yields JSON
// semantically equal to the input for representative PyPI shapes.
// The full corpus check lives in tools/schema-coverage; this test
// pins the high-traffic shapes so a regression surfaces in
// `make test` without running the verifier.
func TestRoundTrip_PyPI(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{
			name: "GHSA top + affected source",
			body: `{"id":"GHSA-x","affected":[{"package":{"ecosystem":"PyPI","name":"pkg"},"database_specific":{"source":"https://example/m.json"}}],"database_specific":{"cwe_ids":["CWE-78"],"github_reviewed":true,"severity":"HIGH"}}`,
		},
		{
			name: "Malicious-packages origin",
			body: `{"id":"MAL-1","affected":[{"package":{"ecosystem":"PyPI","name":"x"},"database_specific":{"source":"https://example/m.json"}}],"database_specific":{"malicious-packages-origins":[{"id":"OSSF-1","import_time":"2023-08-24T15:12:15.962383Z","sha256":"abc","source":"checkmarx","versions":["1.0"]}]}}`,
		},
		{
			name: "Affected severity as label",
			body: `{"id":"OSV-2021-1","affected":[{"package":{"ecosystem":"PyPI","name":"y"},"ecosystem_specific":{"severity":"HIGH"},"database_specific":{"source":"https://example/y.json"}}]}`,
		},
		{
			name: "Affected severity as array",
			body: `{"id":"GHSA-y","affected":[{"package":{"ecosystem":"PyPI","name":"z"},"ecosystem_specific":{"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N"}]},"database_specific":{"source":"https://example/z.json"}}]}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec, err := NewRecordPyPI(strings.NewReader(tc.body))
			if err != nil {
				t.Fatalf("NewRecordPyPI: %v", err)
			}
			out, err := json.Marshal(rec)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			if !equalJSON(t, []byte(tc.body), out) {
				inB, _ := json.MarshalIndent(jsonAny(t, []byte(tc.body)), "", "  ")
				outB, _ := json.MarshalIndent(jsonAny(t, out), "", "  ")
				t.Errorf("round-trip diff:\n in = %s\nout = %s", inB, outB)
			}
		})
	}
}

func equalJSON(t *testing.T, a, b []byte) bool {
	t.Helper()
	aa, _ := json.Marshal(jsonAny(t, a))
	bb, _ := json.Marshal(jsonAny(t, b))
	return bytes.Equal(aa, bb)
}

func jsonAny(t *testing.T, b []byte) any {
	t.Helper()
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("unmarshal %s: %v", b, err)
	}
	return v
}
