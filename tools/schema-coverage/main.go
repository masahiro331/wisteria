// Schema-coverage verifier for internal/unified/{osv,cve,kev}.
//
// Walks <root> (default ./tmp/sources), parses each file two ways:
//
//	A) into the typed schema (osv.Record / cve.Record / kev.Catalog)
//	B) into interface{}
//
// re-marshals both, normalizes empty values, and reports any JSON path
// present in (B) but missing from (A). Sampling per ecosystem / per year
// keeps runtime sane on the full upstream corpus.
//
// This is a dev-time diagnostic, not a runtime tool. It is deliberately
// outside cmd/ and internal/ so it does not ship in the wisteria binary.
//
// Usage from repo root:
//
//	go run ./tools/schema-coverage \
//	    [-root tmp/sources] \
//	    [-per-ecosystem 50] \
//	    [-per-year 50]
//
// Expected output once schemas are in sync with upstream:
//
//	[OSV] no missing fields detected ✅
//	[CVE5] no missing fields detected ✅
//	[KEV] no missing fields detected ✅
//
// EPSS and Exploit-DB are not covered: their parsers read fixed CSV
// schemas, not JSON, so the "interface{} round-trip" approach does
// not apply.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/masahiro331/wisteria/internal/unified/kev"
	"github.com/masahiro331/wisteria/pkg/advisory/cve"
	"github.com/masahiro331/wisteria/pkg/advisory/osv"
)

func main() {
	root := flag.String("root", "tmp/sources", "sources root")
	perEcosystem := flag.Int("per-ecosystem", 50, "OSV files per ecosystem to sample")
	perYear := flag.Int("per-year", 50, "CVE files per year to sample")
	flag.Parse()

	missingOSV := newCounter()
	missingCVE := newCounter()
	missingKEV := newCounter()

	checkOSV(*root, *perEcosystem, missingOSV)
	checkCVE(*root, *perYear, missingCVE)
	checkKEV(*root, missingKEV)

	report("OSV", missingOSV)
	report("CVE5", missingCVE)
	report("KEV", missingKEV)
}

// ----- per-source drivers -----

func checkOSV(root string, perEco int, c *counter) {
	osvRoot := filepath.Join(root, "osv")
	entries, err := os.ReadDir(osvRoot)
	if err != nil {
		fmt.Fprintln(os.Stderr, "osv root:", err)
		return
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		files := sample(filepath.Join(osvRoot, e.Name()), perEco, ".json")
		for _, p := range files {
			diffOne(p, c, func(b []byte) (any, error) {
				var v osv.Record
				err := json.Unmarshal(b, &v)
				return v, err
			})
		}
	}
}

func checkCVE(root string, perYear int, c *counter) {
	cveRoot := filepath.Join(root, "cve")
	// CVE files live under cve/cvelistV5-main/cves/<year>/<bucket>/CVE-*.json
	yearsBase, err := findYearsRoot(cveRoot)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cve year root:", err)
		return
	}
	years, _ := os.ReadDir(yearsBase)
	for _, y := range years {
		if !y.IsDir() {
			continue
		}
		files := sample(filepath.Join(yearsBase, y.Name()), perYear, ".json")
		for _, p := range files {
			diffOne(p, c, func(b []byte) (any, error) {
				var v cve.Record
				err := json.Unmarshal(b, &v)
				return v, err
			})
		}
	}
}

func checkKEV(root string, c *counter) {
	p := filepath.Join(root, "kev", "known_exploited_vulnerabilities.json")
	diffOne(p, c, func(b []byte) (any, error) {
		var v kev.Catalog
		err := json.Unmarshal(b, &v)
		return v, err
	})
}

// ----- diff core -----

func diffOne(path string, c *counter, parseTyped func([]byte) (any, error)) {
	raw, err := os.ReadFile(path)
	if err != nil {
		c.bump("__read_error__:"+err.Error(), path)
		return
	}
	typed, err := parseTyped(raw)
	if err != nil {
		c.bump("__parse_error__:"+simplifyErr(err), path)
		return
	}
	tBytes, err := json.Marshal(typed)
	if err != nil {
		c.bump("__remarshal_error__:"+err.Error(), path)
		return
	}
	var tAny, rAny any
	if err := json.Unmarshal(tBytes, &tAny); err != nil {
		c.bump("__retype_error__:"+err.Error(), path)
		return
	}
	if err := json.Unmarshal(raw, &rAny); err != nil {
		c.bump("__rawtype_error__:"+err.Error(), path)
		return
	}
	missing := []string{}
	collectMissing("", normalize(rAny), normalize(tAny), &missing)
	// Dedup within one file so a path that appears in many array elements
	// still bumps the count by 1 here. Cross-file totals come from the
	// per-file bumps.
	seen := map[string]bool{}
	for _, m := range missing {
		if seen[m] {
			continue
		}
		seen[m] = true
		c.bump(m, path)
	}
}

// collectMissing walks the raw tree; when a key/path appears in raw but not
// in typed, record the path. `null`, `[]`, and `{}` on the raw side are all
// treated as information-equivalent to "absent" — a typed schema is allowed
// to drop them because reading the field yields the zero value either way.
func collectMissing(path string, raw, typed any, out *[]string) {
	switch r := raw.(type) {
	case map[string]any:
		t, _ := typed.(map[string]any)
		for k, rv := range r {
			child := path + "." + k
			if path == "" {
				child = k
			}
			tv, ok := t[k]
			if !ok {
				if isAbsentEquivalent(rv) {
					continue
				}
				*out = append(*out, child)
				continue
			}
			collectMissing(child, rv, tv, out)
		}
	case []any:
		t, _ := typed.([]any)
		// Union every element of raw with the matching element on the typed
		// side (or the first typed element if shorter), so missing fields
		// that only show up in non-leading entries still surface.
		for i, rv := range r {
			var tv any
			switch {
			case i < len(t):
				tv = t[i]
			case len(t) > 0:
				tv = t[0]
			}
			collectMissing(path+"[]", rv, tv, out)
		}
	default:
		// scalars: ignore value diffs (we only care about lost fields)
	}
}

// normalize is a passthrough today. Earlier versions stripped empty values
// to suppress noise, but that masked omitempty-driven dropouts; the diff is
// strict instead, with isAbsentEquivalent handling the narrow exceptions
// (null, [], {}) at the comparison site.
func normalize(v any) any { return v }

// isAbsentEquivalent reports whether a raw upstream value carries no
// information beyond its bare presence — JSON null, an empty array, an
// empty object, or Go's zero time stamp ("0001-01-01T00:00:00Z") that some
// upstream catalogs (e.g. Debian OSV) emit literally for unset fields. The
// typed schema is allowed to drop these via omitzero/omitempty because
// re-reading the field produces the same zero value.
func isAbsentEquivalent(v any) bool {
	switch x := v.(type) {
	case nil:
		return true
	case []any:
		return len(x) == 0
	case map[string]any:
		return len(x) == 0
	case string:
		return x == "0001-01-01T00:00:00Z"
	default:
		return false
	}
}

// ----- helpers -----

// counter tracks per-path occurrence counts and a few example file paths so
// the report points the operator straight at the upstream files to grep.
type counter struct {
	count   map[string]int
	samples map[string][]string
}

const examplesPerPath = 3

func newCounter() *counter {
	return &counter{count: map[string]int{}, samples: map[string][]string{}}
}

func (c *counter) bump(k, samplePath string) {
	c.count[k]++
	if len(c.samples[k]) < examplesPerPath {
		c.samples[k] = append(c.samples[k], samplePath)
	}
}

func report(name string, c *counter) {
	if len(c.count) == 0 {
		fmt.Printf("[%s] no missing fields detected ✅\n", name)
		return
	}
	type kv struct {
		k string
		v int
	}
	rows := make([]kv, 0, len(c.count))
	for k, v := range c.count {
		rows = append(rows, kv{k, v})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].v > rows[j].v })
	fmt.Printf("[%s] missing fields (top 30 by count):\n", name)
	for i, r := range rows {
		if i >= 30 {
			fmt.Printf("  ... and %d more paths\n", len(rows)-30)
			break
		}
		fmt.Printf("  %6d  %s\n", r.v, r.k)
		for _, p := range c.samples[r.k] {
			fmt.Printf("           e.g. %s\n", p)
		}
	}
}

func sample(dir string, n int, ext string) []string {
	var out []string
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(p, ext) {
			return nil
		}
		out = append(out, p)
		if len(out) >= n {
			return fs.SkipAll
		}
		return nil
	})
	return out
}

func findYearsRoot(cveRoot string) (string, error) {
	// cve/cvelistV5-main/cves/<year>/...
	candidates, _ := filepath.Glob(filepath.Join(cveRoot, "*", "cves"))
	if len(candidates) > 0 {
		return candidates[0], nil
	}
	return "", fmt.Errorf("no cves dir under %s", cveRoot)
}

func simplifyErr(err error) string {
	s := err.Error()
	if i := strings.Index(s, " in "); i > 0 {
		return s[:i]
	}
	return s
}
