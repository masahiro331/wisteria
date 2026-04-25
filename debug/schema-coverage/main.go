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
//	go run ./debug/schema-coverage \
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
// EPSS is not covered: its parser is a fixed CSV, not JSON, so the
// "interface{} round-trip" approach does not apply.
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

	"github.com/masahiro331/wisteria/internal/unified/cve"
	"github.com/masahiro331/wisteria/internal/unified/kev"
	"github.com/masahiro331/wisteria/internal/unified/osv"
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
		c.bump("__read_error__:" + err.Error())
		return
	}
	typed, err := parseTyped(raw)
	if err != nil {
		c.bump("__parse_error__:" + simplifyErr(err))
		return
	}
	tBytes, err := json.Marshal(typed)
	if err != nil {
		c.bump("__remarshal_error__:" + err.Error())
		return
	}
	var tAny, rAny any
	if err := json.Unmarshal(tBytes, &tAny); err != nil {
		c.bump("__retype_error__:" + err.Error())
		return
	}
	if err := json.Unmarshal(raw, &rAny); err != nil {
		c.bump("__rawtype_error__:" + err.Error())
		return
	}
	missing := []string{}
	collectMissing("", normalize(rAny), normalize(tAny), &missing)
	for _, m := range missing {
		c.bump(m)
	}
}

// collectMissing walks the raw tree; when a key/path appears in raw but not
// in typed (or differs in non-trivial ways), record the path.
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
				if !isEmpty(rv) {
					*out = append(*out, child)
				}
				continue
			}
			collectMissing(child, rv, tv, out)
		}
	case []any:
		t, _ := typed.([]any)
		// Walk the first element only as a structural sample; arrays are
		// homogeneous in our schemas so this catches missing item-level
		// fields without exploding sample size.
		if len(r) > 0 && len(t) > 0 {
			collectMissing(path+"[]", r[0], t[0], out)
		}
	default:
		// scalars: ignore value diffs (we only care about lost fields)
	}
}

// normalize collapses things our typed schema cannot or does not preserve:
// JSON numbers stay as float64, but maps with empty/null values are dropped
// so they don't show up as "missing" when our schema also omits them.
func normalize(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, vv := range x {
			if isEmpty(vv) {
				continue
			}
			out[k] = normalize(vv)
		}
		return out
	case []any:
		out := make([]any, 0, len(x))
		for _, vv := range x {
			if isEmpty(vv) {
				continue
			}
			out = append(out, normalize(vv))
		}
		return out
	default:
		return v
	}
}

func isEmpty(v any) bool {
	switch x := v.(type) {
	case nil:
		return true
	case string:
		return x == ""
	case []any:
		return len(x) == 0
	case map[string]any:
		return len(x) == 0
	default:
		return false
	}
}

// ----- helpers -----

type counter struct {
	m map[string]int
}

func newCounter() *counter { return &counter{m: map[string]int{}} }
func (c *counter) bump(k string) {
	c.m[k]++
}

func report(name string, c *counter) {
	if len(c.m) == 0 {
		fmt.Printf("[%s] no missing fields detected ✅\n", name)
		return
	}
	type kv struct {
		k string
		v int
	}
	rows := make([]kv, 0, len(c.m))
	for k, v := range c.m {
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
