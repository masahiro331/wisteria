package db_test

import (
	"context"
	"errors"
	"testing"

	"github.com/masahiro331/wisteria/pkg/advisory"
	"github.com/masahiro331/wisteria/pkg/db"
)

// fakeDriver is a no-op Driver used to observe registry dispatch.
type fakeDriver struct {
	dsn string
}

func (d *fakeDriver) Find(_ context.Context, _ string) ([]advisory.UnifiedAdvisory, error) {
	return nil, db.ErrNotFound
}

func (d *fakeDriver) FindByPackage(_ context.Context, _, _ string) ([]advisory.UnifiedAdvisory, error) {
	return nil, nil
}

func (d *fakeDriver) Close() error { return nil }

func TestOpen_DispatchesBySchemeAndPassesDSN(t *testing.T) {
	db.Register("fake", func(_ context.Context, dsn string) (db.Driver, error) {
		return &fakeDriver{dsn: dsn}, nil
	})

	d, err := db.Open(context.Background(), "fake:///some/where")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })

	fake, ok := d.(*fakeDriver)
	if !ok {
		t.Fatalf("Open returned %T, want *fakeDriver", d)
	}
	if fake.dsn != "fake:///some/where" {
		t.Errorf("opener got dsn %q, want the full DSN", fake.dsn)
	}
}

func TestOpen_UnknownSchemeErrors(t *testing.T) {
	_, err := db.Open(context.Background(), "nosuch:///x")
	if !errors.Is(err, db.ErrUnknownScheme) {
		t.Fatalf("err = %v, want ErrUnknownScheme", err)
	}
}

func TestOpen_SchemelessDSNErrors(t *testing.T) {
	_, err := db.Open(context.Background(), "/just/a/path")
	if err == nil {
		t.Fatal("expected error for DSN without scheme")
	}
}

func TestRegister_DuplicateSchemePanics(t *testing.T) {
	opener := func(_ context.Context, _ string) (db.Driver, error) { return &fakeDriver{}, nil }
	db.Register("dup", opener)
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on duplicate Register")
		}
	}()
	db.Register("dup", opener)
}

func TestRegister_EmptySchemePanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on empty scheme")
		}
	}()
	db.Register("", func(_ context.Context, _ string) (db.Driver, error) { return &fakeDriver{}, nil })
}

func TestRegister_NilOpenerPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on nil opener")
		}
	}()
	db.Register("nilop", nil)
}
