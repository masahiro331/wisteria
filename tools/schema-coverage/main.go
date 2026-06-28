// Schema-coverage verifier for internal/unified/{osv,cve,kev}.
//
// Walks <root> (default ./tmp/sources), parses each file two ways:
//
//	A) into the typed schema (osv ecosystem-typed Record /
//	   cve.Record / kev.Catalog)
//	B) into interface{}
//
// re-marshals (A) and diffs against (B). Strict mode: dropped keys,
// fabricated keys, scalar value mismatches, and array length
// mismatches all surface in the report. Sub-second timestamp
// reformatting (Go's `time.Time` re-emits `.327Z` as `.327000000Z`)
// is normalised, and absent-equivalent raw values
// (null / [] / {} / "0001-01-01T00:00:00Z") are silently accepted as
// drops.
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
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/masahiro331/wisteria/internal/unified/cve"
	"github.com/masahiro331/wisteria/internal/unified/kev"
	"github.com/masahiro331/wisteria/internal/unified/osv"
	"github.com/masahiro331/wisteria/internal/unified/osv/ecosystem"
)

func main() {
	root := flag.String("root", "tmp/sources", "sources root")
	perEcosystem := flag.Int("per-ecosystem", 50, "OSV files per ecosystem to sample (0 = no limit)")
	perYear := flag.Int("per-year", 50, "CVE files per year to sample (0 = no limit)")
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
		eco, err := osv.EcosystemFromString(e.Name())
		if err != nil {
			c.bump("__ecosystem_unknown__:"+e.Name(), filepath.Join(osvRoot, e.Name()))
			continue
		}
		files := sample(filepath.Join(osvRoot, e.Name()), perEco, ".json")
		for _, p := range files {
			diffOne(p, c, func(b []byte) (any, error) {
				return ecosystem.Parse(eco, bytes.NewReader(b))
			})
		}
	}
}

func checkCVE(root string, perYear int, c *counter) {
	cveRoot := filepath.Join(root, "cve")
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
	collectDiff("", normalize(rAny), normalize(tAny), &missing)
	seen := map[string]bool{}
	for _, m := range missing {
		if seen[m] {
			continue
		}
		seen[m] = true
		c.bump(m, path)
	}
}

// collectDiff walks both trees and records every path where raw and
// typed disagree — dropped keys (path), fabricated keys ("+"+path),
// array length mismatches (path+":len"), and scalar value mismatches
// (path+":value"). `null` / `[]` / `{}` / `"0001-01-01T00:00:00Z"`
// on the raw side are treated as absent-equivalent; the typed schema
// may legitimately drop them.
//
// Numbers are compared by their decoded float64 form (json.Unmarshal
// into `any` decodes every JSON number that way), so `1` and `1.0`
// agree.
func collectDiff(path string, raw, typed any, out *[]string) {
	if isAbsentEquivalent(raw) {
		return
	}
	switch r := raw.(type) {
	case map[string]any:
		t, ok := typed.(map[string]any)
		if !ok {
			if path == "" {
				*out = append(*out, "<root>:type")
			} else {
				*out = append(*out, path+":type")
			}
			return
		}
		for k, rv := range r {
			child := joinPath(path, k)
			tv, present := t[k]
			if !present {
				if isAbsentEquivalent(rv) {
					continue
				}
				*out = append(*out, child)
				continue
			}
			collectDiff(child, rv, tv, out)
		}
		for k, tv := range t {
			if _, ok := r[k]; ok {
				continue
			}
			if isAbsentEquivalent(tv) {
				continue
			}
			*out = append(*out, "+"+joinPath(path, k))
		}
	case []any:
		t, ok := typed.([]any)
		if !ok {
			*out = append(*out, path+":type")
			return
		}
		if len(r) != len(t) {
			*out = append(*out, path+":len")
			return
		}
		for i, rv := range r {
			collectDiff(path+"[]", rv, t[i], out)
		}
	default:
		if !scalarEqual(raw, typed) {
			if path == "" {
				*out = append(*out, "<root>:value")
			} else {
				*out = append(*out, path+":value")
			}
		}
	}
}

func joinPath(parent, key string) string {
	if parent == "" {
		return key
	}
	return parent + "." + key
}

func scalarEqual(a, b any) bool {
	switch av := a.(type) {
	case float64:
		bv, ok := b.(float64)
		return ok && av == bv
	case string:
		bv, ok := b.(string)
		if !ok {
			return false
		}
		if av == bv {
			return true
		}
		// Two RFC3339 timestamps that parse to the same instant are
		// equal even if their fractional-second textual form differs.
		ta, ea := time.Parse(time.RFC3339Nano, av)
		tb, eb := time.Parse(time.RFC3339Nano, bv)
		return ea == nil && eb == nil && ta.Equal(tb)
	case bool:
		bv, ok := b.(bool)
		return ok && av == bv
	case nil:
		return b == nil
	default:
		return a == b
	}
}

// normalize is a passthrough today.
func normalize(v any) any { return v }

// isAbsentEquivalent reports whether a raw upstream value carries no
// information beyond its bare presence — JSON null, an empty array
// (or one whose every element is absent-equivalent), an empty object
// (or one whose every value is absent-equivalent), or Go's zero time
// stamp ("0001-01-01T00:00:00Z"). Recursive so wrappers like
// `{"malicious-packages-origins": null}` are treated as absent too.
func isAbsentEquivalent(v any) bool {
	switch x := v.(type) {
	case nil:
		return true
	case []any:
		for _, e := range x {
			if !isAbsentEquivalent(e) {
				return false
			}
		}
		return true
	case map[string]any:
		for _, e := range x {
			if !isAbsentEquivalent(e) {
				return false
			}
		}
		return true
	case string:
		return x == "0001-01-01T00:00:00Z"
	default:
		return false
	}
}

// ----- helpers -----

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
		if n > 0 && len(out) >= n {
			return fs.SkipAll
		}
		return nil
	})
	return out
}

func findYearsRoot(cveRoot string) (string, error) {
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
