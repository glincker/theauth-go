package postgres

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestMigrate verifies the runtime applier when a Postgres DSN is available.
// Skipped in environments without THEAUTH_TEST_PG_DSN to keep unit tests
// driver-free. CI runs this against a fresh Postgres container.
func TestMigrate(t *testing.T) {
	dsn := os.Getenv("THEAUTH_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("THEAUTH_TEST_PG_DSN not set; skipping integration migrate test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	// Run against an isolated schema so a re-run on the same DSN is clean.
	schema := "theauth_migrate_test_" + randSuffix()
	if _, err := pool.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	defer func() {
		_, _ = pool.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE")
	}()
	if _, err := pool.Exec(ctx, "SET search_path TO "+schema); err != nil {
		t.Fatalf("search_path: %v", err)
	}

	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("first Migrate: %v", err)
	}

	// Verify the ledger has every shipped version.
	files, err := loadMigrationFiles()
	if err != nil {
		t.Fatalf("loadMigrationFiles: %v", err)
	}
	var ledgerCount int
	if err := pool.QueryRow(ctx, "SELECT COUNT(*) FROM "+migrationsLedger).Scan(&ledgerCount); err != nil {
		t.Fatalf("count ledger: %v", err)
	}
	if ledgerCount != len(files) {
		t.Fatalf("ledger has %d rows, expected %d", ledgerCount, len(files))
	}

	// A second Migrate is a no-op.
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}
	if err := pool.QueryRow(ctx, "SELECT COUNT(*) FROM "+migrationsLedger).Scan(&ledgerCount); err != nil {
		t.Fatalf("count after re-run: %v", err)
	}
	if ledgerCount != len(files) {
		t.Fatalf("re-run changed ledger row count to %d", ledgerCount)
	}
}

func TestLoadMigrationFiles_ordersByVersion(t *testing.T) {
	files, err := loadMigrationFiles()
	if err != nil {
		t.Fatalf("loadMigrationFiles: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("expected at least one embedded migration")
	}
	for i := 1; i < len(files); i++ {
		if files[i-1].version >= files[i].version {
			t.Fatalf("not ordered: %q precedes %q", files[i-1].version, files[i].version)
		}
	}
	// Spot-check the first version naming convention.
	if !strings.HasPrefix(files[0].version, "0001_") {
		t.Fatalf("first migration version should start with 0001_, got %q", files[0].version)
	}
}

func TestAdvisoryLockKey_isDeterministic(t *testing.T) {
	a := advisoryLockKey(migrationsLockName)
	b := advisoryLockKey(migrationsLockName)
	if a != b {
		t.Fatalf("advisoryLockKey not deterministic: %d vs %d", a, b)
	}
	if a == 0 {
		t.Fatal("advisoryLockKey hashed to 0")
	}
}

func randSuffix() string {
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	var b strings.Builder
	for i := 0; i < 8; i++ {
		b.WriteByte(chars[i*7%len(chars)])
	}
	return b.String()
}
