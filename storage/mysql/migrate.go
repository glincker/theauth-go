package mysql

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"hash/fnv"
	"io/fs"
	"sort"
	"strings"
)

//go:embed migrations/*.up.sql
var migrationsFS embed.FS

const (
	migrationsDir    = "migrations"
	migrationsLedger = "theauth_schema_migrations"
)

// Migrate applies every embedded up migration that has not already been
// recorded in theauth_schema_migrations, in version order, under a MySQL
// GET_LOCK advisory lock so concurrent replicas do not race on first boot.
// Returns nil when the schema is at the latest version. Callers should invoke
// Migrate before constructing a Store.
func Migrate(ctx context.Context, db *sql.DB) error {
	files, err := loadMigrationFiles()
	if err != nil {
		return fmt.Errorf("theauth mysql migrate: load embedded migrations: %w", err)
	}

	lockName := advisoryLockName("theauth-go-mysql.migrate")
	if err := acquireMySQLLock(ctx, db, lockName); err != nil {
		return err
	}
	defer func() { _ = releaseMySQLLock(ctx, db, lockName) }()

	ensureSQL := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
		version    VARCHAR(255) PRIMARY KEY,
		applied_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
	)`, migrationsLedger)
	if _, err := db.ExecContext(ctx, ensureSQL); err != nil {
		return fmt.Errorf("ensure ledger table: %w", err)
	}

	applied, err := loadApplied(ctx, db)
	if err != nil {
		return fmt.Errorf("load applied versions: %w", err)
	}

	for _, f := range files {
		if _, ok := applied[f.version]; ok {
			continue
		}
		// MySQL does not always support multi-statement exec in a single
		// call. Split on semicolons and execute each statement individually.
		stmts := splitStatements(f.body)
		for _, stmt := range stmts {
			if _, err := db.ExecContext(ctx, stmt); err != nil {
				return fmt.Errorf("apply migration %s: %w", f.version, err)
			}
		}
		if _, err := db.ExecContext(ctx,
			fmt.Sprintf(`INSERT IGNORE INTO %s (version) VALUES (?)`, migrationsLedger),
			f.version,
		); err != nil {
			return fmt.Errorf("record migration %s: %w", f.version, err)
		}
	}
	return nil
}

// splitStatements splits a SQL file into individual statements by semicolon.
// Empty statements (whitespace-only) are dropped.
func splitStatements(body string) []string {
	parts := strings.Split(body, ";")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		s := strings.TrimSpace(p)
		if s == "" || strings.HasPrefix(s, "--") {
			continue
		}
		// Strip leading comment lines but keep the body.
		lines := strings.Split(s, "\n")
		var kept []string
		for _, l := range lines {
			trimmed := strings.TrimSpace(l)
			if trimmed == "" {
				continue
			}
			kept = append(kept, l)
		}
		if len(kept) > 0 {
			out = append(out, strings.Join(kept, "\n"))
		}
	}
	return out
}

type migrationFile struct {
	version string
	body    string
}

func loadMigrationFiles() ([]migrationFile, error) {
	entries, err := fs.ReadDir(migrationsFS, migrationsDir)
	if err != nil {
		return nil, err
	}
	out := make([]migrationFile, 0, len(entries))
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".up.sql") {
			continue
		}
		body, err := fs.ReadFile(migrationsFS, migrationsDir+"/"+name)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", name, err)
		}
		version := strings.TrimSuffix(name, ".up.sql")
		out = append(out, migrationFile{version: version, body: string(body)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	return out, nil
}

func loadApplied(ctx context.Context, db *sql.DB) (map[string]struct{}, error) {
	rows, err := db.QueryContext(ctx, fmt.Sprintf(`SELECT version FROM %s`, migrationsLedger))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]struct{})
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out[v] = struct{}{}
	}
	return out, rows.Err()
}

// advisoryLockName derives a short lock key from the input string. MySQL
// GET_LOCK accepts an arbitrary string; we use a deterministic abbreviation
// so migrations from multiple theauth instances on the same server do not
// collide with other application locks.
func advisoryLockName(name string) string {
	h := fnv.New64a()
	_, _ = h.Write([]byte(name))
	return fmt.Sprintf("theauth_%d", h.Sum64())
}

func acquireMySQLLock(ctx context.Context, db *sql.DB, name string) error {
	var result sql.NullInt64
	if err := db.QueryRowContext(ctx, `SELECT GET_LOCK(?, 30)`, name).Scan(&result); err != nil {
		return fmt.Errorf("GET_LOCK(%s): %w", name, err)
	}
	if !result.Valid || result.Int64 != 1 {
		return fmt.Errorf("GET_LOCK(%s): could not acquire lock (timeout or error)", name)
	}
	return nil
}

func releaseMySQLLock(ctx context.Context, db *sql.DB, name string) error {
	_, err := db.ExecContext(ctx, `SELECT RELEASE_LOCK(?)`, name)
	return err
}
