// Package indexer is Stage 5 of the unified-advisory pipeline. It builds
// the lookup index that pkg/db drivers use to resolve IDs and packages
// without scanning the whole tree (design docs/design/db-driver.md §6):
//
//	index/meta.json                                  {"version": 1}
//	index/ids/<escaped-id>.json                      ID (PrimaryID + alias) → records
//	index/packages/<escaped-eco>/<escaped-name>.json (ecosystem, name) → records
//
// One entry = one file, mirroring the per-record tree: lookups are O(1)
// direct reads with no in-memory index, and the layout maps verbatim to
// S3 object keys or KVS keys for future tree-shaped backends.
//
// Collect is called from the Stage 2+3 fan-out (one merged record at a
// time, any goroutine); Write flushes the aggregated maps after Stage 4.
// Only strings are retained, so memory stays proportional to the ID and
// package universe, not to record bodies.
package indexer

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"sync"

	"github.com/masahiro331/wisteria/internal/unified/writer"
	"github.com/masahiro331/wisteria/pkg/advisory"
)

// MetaVersion is the index format generation this package writes.
// Drivers must refuse unknown versions.
const MetaVersion = 1

const (
	subdir         = "index"
	metaFile       = "meta.json"
	idsSubdir      = "ids"
	packagesSubdir = "packages"
)

// Meta is the body of index/meta.json.
type Meta struct {
	Version int `json:"version"`
}

// RecordRef points one index entry at one unified record. Path is the
// unified-root-relative slash path produced by writer.RelPath, so it is
// valid on any tree-shaped backend.
type RecordRef struct {
	PrimaryID string `json:"primary_id"`
	Path      string `json:"path"`
}

// Entry is the body of one ids/ or packages/ index file. Records are
// sorted by PrimaryID so lookups are deterministic.
type Entry struct {
	Records []RecordRef `json:"records"`
}

// MetaPath returns the unified-root-relative slash path of meta.json.
func MetaPath() string {
	return path.Join(subdir, metaFile)
}

// IDPath returns the unified-root-relative slash path of the ids entry
// for one ID (PrimaryID or alias). The dynamic segment is PathEscape'd.
func IDPath(id string) string {
	return path.Join(subdir, idsSubdir, url.PathEscape(id)+".json")
}

// PackagePath returns the unified-root-relative slash path of the
// packages entry for one (ecosystem, name) pair. Both dynamic segments
// are PathEscape'd — package names can contain "/" (Go modules), and
// the writer-style "_" replacement could collide two real names.
func PackagePath(ecosystem, name string) string {
	return path.Join(subdir, packagesSubdir, url.PathEscape(ecosystem), url.PathEscape(name)+".json")
}

type pkgKey struct {
	ecosystem string
	name      string
}

// Indexer aggregates (id → record) and (package → record) tuples across
// the Stage 2+3 fan-out. Safe for concurrent Collect calls.
type Indexer struct {
	mu   sync.Mutex
	ids  map[string]map[string]RecordRef // id → PrimaryID → ref
	pkgs map[pkgKey]map[string]RecordRef // (eco, name) → PrimaryID → ref
}

// New returns an empty Indexer.
func New() *Indexer {
	return &Indexer{
		ids:  map[string]map[string]RecordRef{},
		pkgs: map[pkgKey]map[string]RecordRef{},
	}
}

// Collect registers one merged record: its PrimaryID and every SourceID
// under ids, and every OSV affected package under packages. Entries with
// an empty ecosystem or name are skipped — they cannot be looked up.
func (ix *Indexer) Collect(rec advisory.UnifiedAdvisory) error {
	rel, err := writer.RelPath(rec)
	if err != nil {
		return fmt.Errorf("indexer: %w", err)
	}
	ref := RecordRef{PrimaryID: rec.PrimaryID, Path: rel}

	ix.mu.Lock()
	defer ix.mu.Unlock()
	ix.addID(rec.PrimaryID, ref)
	for _, id := range rec.SourceIDs {
		ix.addID(id, ref)
	}
	for _, a := range rec.Affected {
		if a.OSV == nil || a.OSV.Package.Ecosystem == "" || a.OSV.Package.Name == "" {
			continue
		}
		key := pkgKey{ecosystem: a.OSV.Package.Ecosystem, name: a.OSV.Package.Name}
		if ix.pkgs[key] == nil {
			ix.pkgs[key] = map[string]RecordRef{}
		}
		ix.pkgs[key][rec.PrimaryID] = ref
	}
	return nil
}

func (ix *Indexer) addID(id string, ref RecordRef) {
	if id == "" {
		return
	}
	if ix.ids[id] == nil {
		ix.ids[id] = map[string]RecordRef{}
	}
	ix.ids[id][ref.PrimaryID] = ref
}

// Write rebuilds <outDir>/index from scratch: RemoveAll + meta.json +
// one file per collected entry. Per-file atomic via temp + rename, same
// as Stage 3; the whole-tree reset makes reruns idempotent.
func (ix *Indexer) Write(outDir string) error {
	idxDir := filepath.Join(outDir, subdir)
	if err := os.RemoveAll(idxDir); err != nil {
		return fmt.Errorf("indexer: clear %s: %w", idxDir, err)
	}
	if err := os.MkdirAll(idxDir, 0o750); err != nil {
		return fmt.Errorf("indexer: create %s: %w", idxDir, err)
	}
	if err := writeJSON(filepath.Join(outDir, filepath.FromSlash(MetaPath())), Meta{Version: MetaVersion}); err != nil {
		return err
	}

	ix.mu.Lock()
	defer ix.mu.Unlock()
	for id, refs := range ix.ids {
		p := filepath.Join(outDir, filepath.FromSlash(IDPath(id)))
		if err := writeJSON(p, entryOf(refs)); err != nil {
			return err
		}
	}
	for key, refs := range ix.pkgs {
		p := filepath.Join(outDir, filepath.FromSlash(PackagePath(key.ecosystem, key.name)))
		if err := writeJSON(p, entryOf(refs)); err != nil {
			return err
		}
	}
	return nil
}

// entryOf flattens one aggregation map into a deterministic Entry.
func entryOf(refs map[string]RecordRef) Entry {
	e := Entry{Records: make([]RecordRef, 0, len(refs))}
	for _, ref := range refs {
		e.Records = append(e.Records, ref)
	}
	sort.Slice(e.Records, func(i, j int) bool {
		return e.Records[i].PrimaryID < e.Records[j].PrimaryID
	})
	return e
}

// writeJSON marshals v to p atomically (temp + rename), creating the
// parent directory on demand.
func writeJSON(p string, v any) error {
	dir := filepath.Dir(p)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("indexer: mkdir %s: %w", dir, err)
	}
	body, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("indexer: marshal %s: %w", p, err)
	}
	tmp, err := os.CreateTemp(dir, ".index-*")
	if err != nil {
		return fmt.Errorf("indexer: temp file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("indexer: write %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("indexer: close %s: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, p); err != nil {
		return fmt.Errorf("indexer: rename %s -> %s: %w", tmpName, p, err)
	}
	return nil
}
