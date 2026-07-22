// Package fsdb implements db.Driver over a unified advisory tree
// exposed as an fs.FS (design docs/design/db-driver.md §5). Open serves
// the common case of a local <cache-dir>/unified directory; New accepts
// any fs.FS, so a tree-shaped backend (S3, zip, in-memory test fixture)
// plugs in without a new driver. Non-tree backends (KVS, RDB) implement
// db.Driver directly instead.
//
// The package registers itself under the "fs" DSN scheme from init():
//
//	import _ "github.com/masahiro331/wisteria/pkg/db/fsdb"
//
//	d, err := db.Open(ctx, "fs:///home/user/.cache/wisteria/unified")
//
// Lookups go through the Stage 5 index (unified/index/, one entry = one
// file), so Find and FindByPackage are O(1) direct reads. On a tree
// built without Stage 5, Find falls back to the direct cve/<year>/ path
// for CVE-shaped ids; alias and package lookups fail with an explicit
// "no index" error.
package fsdb

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"sync"

	"github.com/masahiro331/wisteria/internal/unified/indexer"
	"github.com/masahiro331/wisteria/internal/unified/writer"
	"github.com/masahiro331/wisteria/pkg/advisory"
	"github.com/masahiro331/wisteria/pkg/db"
)

func init() {
	db.Register("fs", func(_ context.Context, dsn string) (db.Driver, error) {
		return openDSN(dsn)
	})
}

// errNoIndex explains how to make alias / package lookups work on a
// tree that predates Stage 5.
var errNoIndex = errors.New("fsdb: unified tree has no index/ (run `wisteria unify` with Stage 5 support to build it)")

// Driver reads a unified advisory tree through an fs.FS. Safe for
// concurrent use.
type Driver struct {
	fsys fs.FS

	metaOnce sync.Once
	metaErr  error
	indexed  bool
}

var _ db.Driver = (*Driver)(nil)

// New returns a Driver over fsys, whose root must be the unified tree
// itself (the directory holding cve/, standalone/ and index/).
func New(fsys fs.FS) *Driver {
	return &Driver{fsys: fsys}
}

// Open returns a Driver over the local directory dir (a unified tree
// root, typically <cache-dir>/unified).
func Open(dir string) (*Driver, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("fsdb: open %s: %w", dir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("fsdb: %s is not a directory", dir)
	}
	return New(os.DirFS(dir)), nil
}

// openDSN opens the fs:///absolute/path form used with db.Open.
func openDSN(dsn string) (*Driver, error) {
	u, err := url.Parse(dsn)
	if err != nil {
		return nil, fmt.Errorf("fsdb: parse DSN %q: %w", dsn, err)
	}
	if u.Opaque != "" {
		return nil, fmt.Errorf("fsdb: DSN %q is not of the form fs:///absolute/path", dsn)
	}
	if u.Host != "" {
		return nil, fmt.Errorf("fsdb: DSN %q has a host part %q; use fs:///absolute/path", dsn, u.Host)
	}
	if u.Path == "" {
		return nil, fmt.Errorf("fsdb: DSN %q has an empty path; use fs:///absolute/path", dsn)
	}
	return Open(u.Path)
}

// Find implements db.Driver. id may be a PrimaryID or an alias; every
// advisory it resolves to is returned in index order (PrimaryID lex).
func (d *Driver) Find(ctx context.Context, id string) ([]advisory.UnifiedAdvisory, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	indexed, err := d.ensureIndex()
	if err != nil {
		return nil, err
	}
	if !indexed {
		return d.findWithoutIndex(id)
	}

	body, err := fs.ReadFile(d.fsys, indexer.IDPath(id))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("fsdb: id %q: %w", id, db.ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("fsdb: read index entry for %q: %w", id, err)
	}
	var entry indexer.Entry
	if err := json.Unmarshal(body, &entry); err != nil {
		return nil, fmt.Errorf("fsdb: parse index entry for %q: %w", id, err)
	}
	if len(entry.Records) == 0 {
		return nil, fmt.Errorf("fsdb: id %q: %w", id, db.ErrNotFound)
	}
	return d.loadAll(ctx, entry)
}

// FindByPackage implements db.Driver. It requires the Stage 5 index; a
// missing package entry is not an error, just no matches.
func (d *Driver) FindByPackage(ctx context.Context, ecosystem advisory.Ecosystem, name string) ([]advisory.UnifiedAdvisory, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	indexed, err := d.ensureIndex()
	if err != nil {
		return nil, err
	}
	if !indexed {
		return nil, errNoIndex
	}

	body, err := fs.ReadFile(d.fsys, indexer.PackagePath(string(ecosystem), name))
	if errors.Is(err, fs.ErrNotExist) {
		return []advisory.UnifiedAdvisory{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("fsdb: read package entry (%s, %s): %w", ecosystem, name, err)
	}
	var entry indexer.Entry
	if err := json.Unmarshal(body, &entry); err != nil {
		return nil, fmt.Errorf("fsdb: parse package entry (%s, %s): %w", ecosystem, name, err)
	}
	return d.loadAll(ctx, entry)
}

// Close implements db.Driver. The fs.FS needs no teardown.
func (d *Driver) Close() error { return nil }

// ensureIndex reads index/meta.json once. (false, nil) means the tree
// has no index at all; an unsupported version is a hard error so a
// future format bump cannot be silently misread.
func (d *Driver) ensureIndex() (bool, error) {
	d.metaOnce.Do(func() {
		body, err := fs.ReadFile(d.fsys, indexer.MetaPath())
		if errors.Is(err, fs.ErrNotExist) {
			return
		}
		if err != nil {
			d.metaErr = fmt.Errorf("fsdb: read %s: %w", indexer.MetaPath(), err)
			return
		}
		var meta indexer.Meta
		if err := json.Unmarshal(body, &meta); err != nil {
			d.metaErr = fmt.Errorf("fsdb: parse %s: %w", indexer.MetaPath(), err)
			return
		}
		if meta.Version != indexer.MetaVersion {
			d.metaErr = fmt.Errorf("fsdb: unsupported index version %d (this build supports %d)",
				meta.Version, indexer.MetaVersion)
			return
		}
		d.indexed = true
	})
	return d.indexed, d.metaErr
}

// findWithoutIndex serves trees that predate Stage 5: CVE-shaped ids
// have a computable path (writer.CVERelPath, the Stage 3 routing rule),
// everything else needs the index.
func (d *Driver) findWithoutIndex(id string) ([]advisory.UnifiedAdvisory, error) {
	rel, ok := writer.CVERelPath(id)
	if !ok {
		return nil, fmt.Errorf("fsdb: id %q: %w", id, errNoIndex)
	}
	rec, err := d.load(rel)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("fsdb: id %q: %w", id, db.ErrNotFound)
	}
	if err != nil {
		return nil, err
	}
	return []advisory.UnifiedAdvisory{rec}, nil
}

// loadAll reads every record an index entry points at, preserving the
// entry's (PrimaryID-sorted) order. A dangling path is a broken index,
// not a not-found.
func (d *Driver) loadAll(ctx context.Context, entry indexer.Entry) ([]advisory.UnifiedAdvisory, error) {
	out := make([]advisory.UnifiedAdvisory, 0, len(entry.Records))
	for _, ref := range entry.Records {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		rec, err := d.load(ref.Path)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, nil
}

// load reads and decodes one record by its unified-root-relative slash
// path. The wrapped error preserves fs.ErrNotExist for callers that
// need to distinguish missing from broken.
func (d *Driver) load(rel string) (advisory.UnifiedAdvisory, error) {
	var rec advisory.UnifiedAdvisory
	body, err := fs.ReadFile(d.fsys, rel)
	if err != nil {
		return rec, fmt.Errorf("fsdb: read record %s: %w", rel, err)
	}
	if err := json.Unmarshal(body, &rec); err != nil {
		return rec, fmt.Errorf("fsdb: parse record %s: %w", rel, err)
	}
	return rec, nil
}
