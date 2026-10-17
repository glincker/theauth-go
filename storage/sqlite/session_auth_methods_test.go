package sqlite_test

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	sqlitestore "github.com/glincker/theauth-go/storage/sqlite"
	"github.com/glincker/theauth-go/v2/storagetest"
)

// newAuthMethodsStore opens a migrated file database of its own, with the
// pragmas the production setup uses.
func newAuthMethodsStore(t *testing.T, opts ...sqlitestore.Option) *sqlitestore.Store {
	t.Helper()
	dsn := "file:" + filepath.Join(t.TempDir(), "auth_methods.db") +
		"?_pragma=foreign_keys(1)&_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)&_txlock=immediate"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := sqlitestore.Migrate(context.Background(), db, opts...); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	s, err := sqlitestore.New(db, opts...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func TestSessionAuthMethods(t *testing.T) {
	t.Parallel()
	storagetest.RunSessionAuthMethods(t, newAuthMethodsStore(t))
}

func TestSessionAuthMethodsCustomPrefix(t *testing.T) {
	t.Parallel()
	storagetest.RunSessionAuthMethods(t, newAuthMethodsStore(t, sqlitestore.WithTablePrefix("auth_x_")))
}
