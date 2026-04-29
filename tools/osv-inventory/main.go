// OSV key-inventory tool.
//
// Walks <root>/osv/<ecosystem>/*.json and reports the union of keys
// observed at the four free-form blob sites:
//
//  1. .database_specific
//  2. .affected[].ecosystem_specific
//  3. .affected[].database_specific
//  4. .affected[].ranges[].database_specific
//
// Output is grouped per ecosystem so a Go struct definition can be
// derived directly. Use this whenever a new OSV ecosystem appears or a
// known one ships a new key — the round-trip verifier will refuse to
// merge until the typed schema covers every reported key.
//
// Defaults to a full scan (no sampling cap). Per-ecosystem walks run
// sequentially; within an ecosystem files are parsed by a worker pool.
//
// Run from repo root:
//
//	go run ./tools/osv-inventory [-root tmp/sources] [-concurrency 0]
//
// `-concurrency 0` (default) uses runtime.NumCPU. `-limit N` (default 0
// = no limit) caps per-ecosystem files for quick smoke runs.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
)

func main() {
	root := flag.String("root", "tmp/sources", "sources root (expects <root>/osv/<eco>/*.json)")
	limit := flag.Int("limit", 0, "max files per ecosystem (0 = no limit)")
	concurrency := flag.Int("concurrency", 0, "parser workers per ecosystem (0 = NumCPU)")
	flag.Parse()

	if *concurrency <= 0 {
		*concurrency = runtime.NumCPU()
	}

	osvRoot := filepath.Join(*root, "osv")
	ecos, err := os.ReadDir(osvRoot)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read osv root:", err)
		os.Exit(1)
	}
	sort.Slice(ecos, func(i, j int) bool { return ecos[i].Name() < ecos[j].Name() })

	for _, e := range ecos {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(osvRoot, e.Name())
		inv := scan(dir, *limit, *concurrency)
		report(e.Name(), inv)
	}
}

type inventory struct {
	mu     sync.Mutex
	files  int
	top    map[string]struct{}
	affEco map[string]struct{}
	affDB  map[string]struct{}
	rngDB  map[string]struct{}
}

func newInventory() *inventory {
	return &inventory{
		top:    map[string]struct{}{},
		affEco: map[string]struct{}{},
		affDB:  map[string]struct{}{},
		rngDB:  map[string]struct{}{},
	}
}

func (inv *inventory) merge(files int, top, affEco, affDB, rngDB map[string]struct{}) {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	inv.files += files
	for k := range top {
		inv.top[k] = struct{}{}
	}
	for k := range affEco {
		inv.affEco[k] = struct{}{}
	}
	for k := range affDB {
		inv.affDB[k] = struct{}{}
	}
	for k := range rngDB {
		inv.rngDB[k] = struct{}{}
	}
}

// scan parses every *.json in dir using `concurrency` workers and merges
// their key-set discoveries into one inventory. Each worker keeps its
// own per-call sets and merges in batch to keep lock contention down.
func scan(dir string, limit, concurrency int) *inventory {
	files := listJSON(dir, limit)
	inv := newInventory()
	if len(files) == 0 {
		return inv
	}
	jobs := make(chan string, concurrency*2)
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			localTop := map[string]struct{}{}
			localAffEco := map[string]struct{}{}
			localAffDB := map[string]struct{}{}
			localRngDB := map[string]struct{}{}
			localFiles := 0
			for p := range jobs {
				b, err := os.ReadFile(p)
				if err != nil {
					continue
				}
				var doc map[string]any
				if err := json.Unmarshal(b, &doc); err != nil {
					continue
				}
				localFiles++
				collectKeys(doc["database_specific"], localTop)
				if aff, ok := doc["affected"].([]any); ok {
					for _, a := range aff {
						am, _ := a.(map[string]any)
						collectKeys(am["ecosystem_specific"], localAffEco)
						collectKeys(am["database_specific"], localAffDB)
						if rngs, ok := am["ranges"].([]any); ok {
							for _, r := range rngs {
								rm, _ := r.(map[string]any)
								collectKeys(rm["database_specific"], localRngDB)
							}
						}
					}
				}
			}
			inv.merge(localFiles, localTop, localAffEco, localAffDB, localRngDB)
		}()
	}
	for _, p := range files {
		jobs <- p
	}
	close(jobs)
	wg.Wait()
	return inv
}

func listJSON(dir string, limit int) []string {
	var out []string
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(p, ".json") {
			return nil
		}
		out = append(out, p)
		if limit > 0 && len(out) >= limit {
			return fs.SkipAll
		}
		return nil
	})
	return out
}

// collectKeys records the top-level keys of v into out, if v is an object.
// Anything else (nil / array / scalar) is silently ignored — callers care
// only about the field membership at each blob site.
func collectKeys(v any, out map[string]struct{}) {
	m, ok := v.(map[string]any)
	if !ok {
		return
	}
	for k := range m {
		out[k] = struct{}{}
	}
}

func report(eco string, inv *inventory) {
	fmt.Printf("=== %s (%d files scanned) ===\n", eco, inv.files)
	if inv.files == 0 {
		fmt.Println("  (no files)")
		return
	}
	printSet("  top    .database_specific            ", inv.top)
	printSet("  affEco .affected[].ecosystem_specific", inv.affEco)
	printSet("  affDB  .affected[].database_specific ", inv.affDB)
	printSet("  rngDB  .ranges[].database_specific   ", inv.rngDB)
}

func printSet(label string, set map[string]struct{}) {
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		fmt.Printf("%s: -\n", label)
		return
	}
	fmt.Printf("%s: %s\n", label, strings.Join(keys, ", "))
}
