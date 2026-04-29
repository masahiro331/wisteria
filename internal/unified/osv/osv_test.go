package osv

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

// TestParse_PyPI_DatabaseSpecificTyped — Parse must dispatch on the
// ecosystem segment of `path` and decode `database_specific` into the
// PyPI-specific struct (no json.RawMessage in flight). This is the
// minimum Green that proves the per-ecosystem pipeline is wired up.
func TestParse_PyPI_DatabaseSpecificTyped(t *testing.T) {
	const body = `{
		"id": "GHSA-pypi-x",
		"affected": [{"package": {"ecosystem": "PyPI", "name": "pkg"}}],
		"database_specific": {
			"cwe_ids": ["CWE-78"],
			"github_reviewed": true,
			"github_reviewed_at": "2026-04-08T21:52:10Z",
			"nvd_published_at": "2026-04-09T20:16:27Z",
			"severity": "CRITICAL"
		}
	}`
	got, err := Parse("tmp/sources/osv/PyPI/GHSA-pypi-x.json", []byte(body))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	spec, ok := got.DatabaseSpecific.(*TopPyPI)
	if !ok {
		t.Fatalf("DatabaseSpecific type = %T, want *TopPyPI", got.DatabaseSpecific)
	}
	if spec.Severity != "CRITICAL" {
		t.Errorf("Severity = %q", spec.Severity)
	}
	if !spec.GitHubReviewed {
		t.Errorf("GitHubReviewed = false")
	}
	if len(spec.CWEIDs) != 1 || spec.CWEIDs[0] != "CWE-78" {
		t.Errorf("CWEIDs = %v", spec.CWEIDs)
	}
}

// TestParse_RoundTripPreservesBytes — parse → re-marshal must produce
// JSON semantically equivalent to the input for a representative PyPI
// record. Strict round-trip is the load-bearing guarantee of the whole
// per-ecosystem refactor.
func TestParse_PyPI_RoundTrip(t *testing.T) {
	const body = `{"id":"GHSA-pypi-x","affected":[{"package":{"ecosystem":"PyPI","name":"pkg"},"database_specific":{"source":"https://example/pypi/x.json"}}],"database_specific":{"cwe_ids":["CWE-78"],"github_reviewed":true,"severity":"CRITICAL"}}`
	got, err := Parse("tmp/sources/osv/PyPI/x.json", []byte(body))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	out, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var rawIn, rawOut any
	if err := json.Unmarshal([]byte(body), &rawIn); err != nil {
		t.Fatalf("unmarshal in: %v", err)
	}
	if err := json.Unmarshal(out, &rawOut); err != nil {
		t.Fatalf("unmarshal out: %v", err)
	}
	if !equalJSON(rawIn, rawOut) {
		t.Errorf("round-trip diff:\n in = %s\nout = %s", body, out)
	}
}

func equalJSON(a, b any) bool {
	ab, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	return bytes.Equal(ab, bb)
}

func TestParse_PYSEC_MultiAlias(t *testing.T) {
	const body = `{
		"id": "PYSEC-2021-872",
		"aliases": ["CVE-2021-42343", "GHSA-hwqr-f3v9-hwxr", "GHSA-j8fq-86c5-5v2r", "PYSEC-2021-387", "PYSEC-2021-871"],
		"summary": "Dask remote code execution.",
		"details": "Dask 2021.10.0 and earlier ...",
		"references": [
			{"type": "ADVISORY", "url": "https://github.com/dask/dask/security/advisories/GHSA-hwqr-f3v9-hwxr"},
			{"type": "FIX", "url": "https://github.com/dask/dask/commit/abcdef"}
		],
		"severity": [
			{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
		],
		"affected": [
			{
				"package": {"ecosystem": "PyPI", "name": "dask", "purl": "pkg:pypi/dask"},
				"ranges": [
					{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2021.10.0"}]}
				],
				"versions": ["2021.9.1", "2021.9.0"]
			}
		]
	}`

	got, err := Parse("tmp/sources/osv/PyPI/PYSEC-2021-872.json", []byte(body))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if got.ID != "PYSEC-2021-872" {
		t.Errorf("ID = %q", got.ID)
	}
	if len(got.Aliases) != 5 || got.Aliases[0] != "CVE-2021-42343" {
		t.Errorf("Aliases = %v", got.Aliases)
	}
	if got.Summary == "" || got.Details == "" {
		t.Errorf("Summary/Details should be populated")
	}
	if len(got.References) != 2 || got.References[1].Type != "FIX" {
		t.Errorf("References = %#v", got.References)
	}
	if len(got.Severity) != 1 || got.Severity[0].Type != "CVSS_V3" {
		t.Errorf("Severity = %#v", got.Severity)
	}

	if len(got.Affected) != 1 {
		t.Fatalf("Affected len = %d", len(got.Affected))
	}
	a0 := got.Affected[0]
	if a0.Package.Ecosystem != "PyPI" || a0.Package.Name != "dask" {
		t.Errorf("Package = %#v", a0.Package)
	}
	if len(a0.Ranges) != 1 || a0.Ranges[0].Type != "ECOSYSTEM" {
		t.Errorf("Ranges = %#v", a0.Ranges)
	}
	if len(a0.Ranges[0].Events) != 2 || a0.Ranges[0].Events[0].Introduced != "0" || a0.Ranges[0].Events[1].Fixed != "2021.10.0" {
		t.Errorf("Events = %#v", a0.Ranges[0].Events)
	}
	if len(a0.Versions) != 2 {
		t.Errorf("Versions len = %d", len(a0.Versions))
	}
}

func TestParse_PyPI_FullTopLevelMetadata(t *testing.T) {
	const body = `{
		"schema_version": "1.7.3",
		"id": "GHSA-xyz",
		"published": "2009-11-20T18:30:00.327Z",
		"modified": "2025-11-19T05:57:42.162407Z",
		"withdrawn": "2025-11-20T00:00:00Z",
		"upstream": ["CVE-2009-3895"],
		"related": ["GHSA-xyz-other"],
		"credits": [
			{"name": "Checkmarx", "contact": ["a@b", "https://example"], "type": "FINDER"}
		],
		"database_specific": {"severity": "CRITICAL", "github_reviewed": true}
	}`
	got, err := Parse("tmp/sources/osv/PyPI/GHSA-xyz.json", []byte(body))
	if err != nil {
		t.Fatalf("Parse: %v", err)
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
	if len(got.Upstream) != 1 || got.Upstream[0] != "CVE-2009-3895" {
		t.Errorf("Upstream = %v", got.Upstream)
	}
	if len(got.Credits) != 1 || got.Credits[0].Name != "Checkmarx" || got.Credits[0].Type != "FINDER" {
		t.Errorf("Credits = %#v", got.Credits)
	}
	if len(got.Credits[0].Contact) != 2 {
		t.Errorf("Contact = %v", got.Credits[0].Contact)
	}
	spec, ok := got.DatabaseSpecific.(*TopPyPI)
	if !ok {
		t.Fatalf("DatabaseSpecific = %T, want *TopPyPI", got.DatabaseSpecific)
	}
	if spec.Severity != "CRITICAL" || !spec.GitHubReviewed {
		t.Errorf("TopPyPI = %#v", spec)
	}
}

// TestParse_UnknownEcosystem — the dispatch table is closed: any
// ecosystem dir we did not register must hard-error so a new upstream
// ecosystem cannot silently land in production with its blobs dropped.
func TestParse_UnknownEcosystem(t *testing.T) {
	const body = `{"id": "X-1"}`
	if _, err := Parse("tmp/sources/osv/UnknownEco/X-1.json", []byte(body)); err == nil {
		t.Fatal("Parse must error on unknown ecosystem")
	}
}

// TestParse_EcosystemRoundTrips picks one representative shape per
// ecosystem family and confirms parse → marshal yields a JSON document
// semantically identical to the input. The full-corpus check lives in
// tools/schema-coverage; this tests pin the high-traffic shapes so a
// regression surfaces in `make test` rather than only via the verifier
// run.
func TestParse_EcosystemRoundTrips(t *testing.T) {
	cases := []struct {
		name string
		path string
		body string
	}{
		{
			name: "Maven GHSA",
			path: "tmp/sources/osv/Maven/x.json",
			body: `{"id":"GHSA-x","affected":[{"package":{"ecosystem":"Maven","name":"a:b"},"database_specific":{"source":"https://example/m.json"}}],"database_specific":{"cwe_ids":["CWE-78"],"github_reviewed":true,"severity":"HIGH"}}`,
		},
		{
			name: "Bitnami CPEs",
			path: "tmp/sources/osv/Bitnami/x.json",
			body: `{"id":"BIT-x","affected":[{"package":{"ecosystem":"Bitnami","name":"foo"},"database_specific":{"source":"https://example/b.json"}}],"database_specific":{"cpes":["cpe:2.3:a:x:y:1:*:*:*:*:*:*:*"],"severity":"High"}}`,
		},
		{
			name: "Ubuntu binaries flat",
			path: "tmp/sources/osv/Ubuntu/x.json",
			body: `{"id":"UBUNTU-x","affected":[{"package":{"ecosystem":"Ubuntu:24.04","name":"pkg"},"ecosystem_specific":{"binaries":[{"binary_name":"libfoo","binary_version":"1.0"}]},"database_specific":{"source":"https://example/u.json"}}]}`,
		},
		{
			name: "Ubuntu binaries dynamic",
			path: "tmp/sources/osv/Ubuntu/x.json",
			body: `{"id":"USN-x","affected":[{"package":{"ecosystem":"Ubuntu:22.04","name":"linux"},"ecosystem_specific":{"binaries":[{"linux-image-oem-22.04":"6.5.0.1022.24"}]},"database_specific":{"source":"https://example/u.json"}}]}`,
		},
		{
			name: "SUSE dynamic binaries",
			path: "tmp/sources/osv/SUSE/x.json",
			body: `{"id":"SUSE-x","affected":[{"package":{"ecosystem":"SUSE:SLES:15","name":"k"},"ecosystem_specific":{"binaries":[{"kernel":"3-1.1"}]},"database_specific":{"source":"https://example/s.json"}}]}`,
		},
		{
			name: "Rocky range yum_repository",
			path: "tmp/sources/osv/Rocky Linux/x.json",
			body: `{"id":"RLSA-x","affected":[{"package":{"ecosystem":"Rocky Linux:9","name":"p"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}],"database_specific":{"yum_repository":"CRB"}}],"database_specific":{"source":"https://example/r.json"}}]}`,
		},
		{
			name: "Debian urgency",
			path: "tmp/sources/osv/Debian/x.json",
			body: `{"id":"DEB-x","affected":[{"package":{"ecosystem":"Debian:12","name":"p"},"ecosystem_specific":{"urgency":"low"},"database_specific":{"source":"https://example/d.json"}}]}`,
		},
		{
			name: "Go review_status",
			path: "tmp/sources/osv/Go/x.json",
			body: `{"id":"GO-x","affected":[{"package":{"ecosystem":"Go","name":"github.com/x/y"},"database_specific":{"source":"https://example/g.json"}}],"database_specific":{"review_status":"REVIEWED","url":"https://pkg.go.dev/vuln/GO-x"}}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Parse(tc.path, []byte(tc.body))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			out, err := json.Marshal(got)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			var rawIn, rawOut any
			if err := json.Unmarshal([]byte(tc.body), &rawIn); err != nil {
				t.Fatalf("unmarshal in: %v", err)
			}
			if err := json.Unmarshal(out, &rawOut); err != nil {
				t.Fatalf("unmarshal out: %v", err)
			}
			if !equalJSON(rawIn, rawOut) {
				inB, _ := json.MarshalIndent(rawIn, "", "  ")
				outB, _ := json.MarshalIndent(rawOut, "", "  ")
				t.Errorf("round-trip diff:\n in = %s\nout = %s", inB, outB)
			}
		})
	}
}
