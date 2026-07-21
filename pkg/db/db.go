// Package db defines the pluggable, read-only driver interface for a
// built Wisteria database plus a database/sql-style DSN registry
// (design docs/design/db-driver.md §4). The advisory data may live on a
// local filesystem, in an object store, a KVS, or an RDB — callers pick
// a backend by DSN scheme and program against the Driver interface:
//
//	import (
//		"github.com/masahiro331/wisteria/pkg/db"
//		_ "github.com/masahiro331/wisteria/pkg/db/fsdb" // register "fs"
//	)
//
//	d, err := db.Open(ctx, "fs:///home/user/.cache/wisteria/unified")
//	defer d.Close()
//	advs, err := d.Find(ctx, "GHSA-xxxx-yyyy-zzzz")
//
// Backend packages register themselves from init() via Register, so a
// blank import is all it takes to make a scheme available. External
// modules can register their own drivers the same way.
package db

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sync"

	"github.com/masahiro331/wisteria/pkg/advisory"
)

// ErrNotFound is returned (wrapped) by Driver.Find when the given id
// resolves to no advisory. Test with errors.Is.
var ErrNotFound = errors.New("db: advisory not found")

// ErrUnknownScheme is returned (wrapped) by Open when no driver is
// registered for the DSN's scheme. Test with errors.Is.
var ErrUnknownScheme = errors.New("db: unknown driver scheme")

// Driver is the read API over a built Wisteria database. Implementations
// must be safe for concurrent use.
type Driver interface {
	// Find returns every UnifiedAdvisory the given id resolves to. id
	// may be a PrimaryID (CVE-ID or standalone ID) or an alias (GHSA,
	// PYSEC, ...); an alias held by an OSV record with multiple CVE
	// aliases resolves to multiple advisories, ordered by PrimaryID.
	// A miss returns an error wrapping ErrNotFound.
	Find(ctx context.Context, id string) ([]advisory.UnifiedAdvisory, error)

	// FindByPackage returns every UnifiedAdvisory whose OSV affected
	// block matches (ecosystem, name) exactly, ordered by PrimaryID.
	// It does not evaluate version ranges — callers check Affected
	// themselves. No match returns an empty slice and a nil error.
	FindByPackage(ctx context.Context, ecosystem, name string) ([]advisory.UnifiedAdvisory, error)

	// Close releases backend resources. Safe to call once.
	Close() error
}

// OpenerFunc opens a Driver from a full DSN. The DSN is passed verbatim
// (scheme included) so drivers can parse backend-specific options.
type OpenerFunc func(ctx context.Context, dsn string) (Driver, error)

var (
	driversMu sync.RWMutex
	drivers   = map[string]OpenerFunc{}
)

// Register makes a driver available under the given DSN scheme. It is
// intended to be called from a driver package's init(); like
// database/sql, it panics on an empty scheme, a nil opener, or a
// duplicate registration — all programming errors.
func Register(scheme string, opener OpenerFunc) {
	driversMu.Lock()
	defer driversMu.Unlock()
	if scheme == "" {
		panic("db: Register scheme is empty")
	}
	if opener == nil {
		panic("db: Register opener is nil")
	}
	if _, dup := drivers[scheme]; dup {
		panic("db: Register called twice for scheme " + scheme)
	}
	drivers[scheme] = opener
}

// Open parses dsn, looks up the driver registered for its scheme, and
// delegates. An unregistered scheme yields an error wrapping
// ErrUnknownScheme.
func Open(ctx context.Context, dsn string) (Driver, error) {
	u, err := url.Parse(dsn)
	if err != nil {
		return nil, fmt.Errorf("db: parse DSN %q: %w", dsn, err)
	}
	if u.Scheme == "" {
		return nil, fmt.Errorf("db: DSN %q has no scheme", dsn)
	}
	driversMu.RLock()
	opener, ok := drivers[u.Scheme]
	driversMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("db: scheme %q: %w", u.Scheme, ErrUnknownScheme)
	}
	return opener(ctx, dsn)
}
