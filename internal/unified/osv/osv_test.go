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

// TestRoundTrip_PerEcosystem pins one representative JSON shape per
// ecosystem-payload family (simple / distro / ghsa / freeform /
// falsepositive) and confirms parse → marshal stays semantically
// equal through the `Parse` dispatch path. The full corpus check
// lives in
// tools/schema-coverage; this guards the typed schema for the
// non-PyPI ecosystems in `make test` so a struct that silently rots
// (a renamed json tag, a dropped field, an IsZero regression) fails
// fast. When a new ecosystem lands, add a case here.
func TestRoundTrip_PerEcosystem(t *testing.T) {
	cases := []struct {
		name string
		eco  Ecosystem
		body string
	}{
		{
			name: "Alpine simple source",
			eco:  EcosystemAlpine,
			body: `{"id":"CVE-2024-0001","affected":[{"package":{"ecosystem":"Alpine:v3.19","name":"openssl"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"3.1.0-r1"}]}],"database_specific":{"source":"https://example/alpine.json"}}]}`,
		},
		{
			name: "Debian ecosystem_specific urgency",
			eco:  EcosystemDebian,
			body: `{"id":"DSA-1","affected":[{"package":{"ecosystem":"Debian:12","name":"curl"},"ecosystem_specific":{"urgency":"high"},"database_specific":{"source":"https://example/debian.json"}}]}`,
		},
		{
			name: "Ubuntu binaries + cves_map",
			eco:  EcosystemUbuntu,
			body: `{"id":"USN-1","affected":[{"package":{"ecosystem":"Ubuntu:22.04:LTS","name":"nginx"},"ecosystem_specific":{"ubuntu_priority":"medium","binaries":[{"binary_name":"nginx-core","binary_version":"1.18.0"}]},"database_specific":{"cves_map":{"CVE-2024-9999":{"status":"released"}},"source":"https://example/ubuntu.json"}}]}`,
		},
		{
			name: "Go top metadata + ecosystem imports",
			eco:  EcosystemGo,
			body: `{"id":"GO-2024-0001","affected":[{"package":{"ecosystem":"Go","name":"golang.org/x/net"},"ecosystem_specific":{"imports":[{"path":"golang.org/x/net/http2","symbols":["Server"]}]},"database_specific":{"source":"https://example/go.json"}}],"database_specific":{"review_status":"REVIEWED","url":"https://pkg.go.dev/vuln/GO-2024-0001"}}`,
		},
		{
			name: "GHC top home/repository",
			eco:  EcosystemGHC,
			body: `{"id":"HSEC-1","affected":[{"package":{"ecosystem":"GHC","name":"base"},"database_specific":{"osv":"HSEC","source":"https://example/ghc.json"}}],"database_specific":{"home":"https://example","repository":"https://example/repo"}}`,
		},
		{
			name: "Maven GHSA top cwe_ids preserved as empty array",
			eco:  EcosystemMaven,
			body: `{"id":"GHSA-m","affected":[{"package":{"ecosystem":"Maven","name":"org.example:lib"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.2.3"}]}],"database_specific":{"ghsa":"GHSA-m","source":"https://example/maven.json"}}],"database_specific":{"cwe_ids":[],"github_reviewed":true,"severity":"HIGH"}}`,
		},
		{
			name: "Maven per-affected cvss object form",
			eco:  EcosystemMaven,
			body: `{"id":"MAL-m","affected":[{"package":{"ecosystem":"Maven","name":"org.example:bad"},"database_specific":{"cvss":{"score":9.8,"vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},"source":"https://example/maven.json"}}]}`,
		},
		{
			// `false_positive` is an omitempty bool, so it only
			// survives the round-trip when set true — exactly the
			// regression a value-typed range database_specific would
			// risk dropping.
			name: "Chainguard range false_positive",
			eco:  EcosystemChainguard,
			body: `{"id":"CGA-1","affected":[{"package":{"ecosystem":"Chainguard","name":"openssl"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"3.1.0"}],"database_specific":{"false_positive":true}}],"database_specific":{"source":"https://example/chainguard.json"}}]}`,
		},
		{
			name: "Rocky Linux range yum_repository",
			eco:  EcosystemRockyLinux,
			body: `{"id":"RLSA-1","affected":[{"package":{"ecosystem":"Rocky Linux:9","name":"kernel"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"5.14.0-1.el9"}],"database_specific":{"yum_repository":"BaseOS"}}],"database_specific":{"source":"https://example/rocky.json"}}]}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec, err := Parse(tc.eco, strings.NewReader(tc.body))
			if err != nil {
				t.Fatalf("Parse(%s): %v", tc.eco, err)
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
