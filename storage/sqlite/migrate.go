package sqlite

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"time"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

// Migration is one forward-only schema step.
type Migration struct {
	// Version is the file name without the .sql suffix, for example 0001_core.
	Version string
	SQL     string
}

// Migrations returns the numbered forward-only .sql files, in the root of the FS, using the default table prefix.
func Migrations() fs.FS {
	sub, err := fs.Sub(migrationFiles, "migrations")
	if err != nil {
		panic(fmt.Sprintf("theauth sqlite: embedded migrations: %v", err))
	}
	return sub
}

// RenderMigrations returns the migrations in version order with the table prefix applied.
func RenderMigrations(opts ...Option) ([]Migration, error) {
	c, err := buildConfig(opts)
	if err != nil {
		return nil, err
	}
	entries, err := fs.ReadDir(migrationFiles, "migrations")
	if err != nil {
		return nil, fmt.Errorf("theauth sqlite: read embedded migrations: %w", err)
	}
	out := make([]Migration, 0, len(entries))
	for _, e := range entries {
		body, err := fs.ReadFile(migrationFiles, "migrations/"+e.Name())
		if err != nil {
			return nil, fmt.Errorf("theauth sqlite: read %s: %w", e.Name(), err)
		}
		out = append(out, Migration{
			Version: strings.TrimSuffix(e.Name(), ".sql"),
			SQL:     strings.ReplaceAll(string(body), DefaultTablePrefix, c.prefix),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	return out, nil
}

// Migrate applies pending migrations tracked in its own <prefix>schema_migrations table.
//
// Each step runs under BEGIN IMMEDIATE so concurrent processes serialize, and
// is recorded in the same transaction as its DDL.
func Migrate(ctx context.Context, db *sql.DB, opts ...Option) error {
	c, err := buildConfig(opts)
	if err != nil {
		return err
	}
	migs, err := RenderMigrations(opts...)
	if err != nil {
		return err
	}
	ledger := c.prefix + "schema_migrations"

	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("theauth sqlite: migrate: acquire connection: %w", err)
	}
	defer func() { _ = conn.Close() }()

	if _, err := conn.ExecContext(ctx, fmt.Sprintf(
		`CREATE TABLE IF NOT EXISTS %s (version TEXT PRIMARY KEY, applied_at INTEGER NOT NULL)`, ledger)); err != nil {
		return fmt.Errorf("theauth sqlite: migrate: create ledger: %w", err)
	}
	for _, m := range migs {
		if err := applyMigration(ctx, conn, ledger, m); err != nil {
			return fmt.Errorf("theauth sqlite: migrate %s: %w", m.Version, err)
		}
	}
	return nil
}

func applyMigration(ctx context.Context, conn *sql.Conn, ledger string, m Migration) (err error) {
	if _, err = conn.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_, _ = conn.ExecContext(context.WithoutCancel(ctx), `ROLLBACK`)
		}
	}()
	var seen int
	switch qerr := conn.QueryRowContext(ctx, `SELECT 1 FROM `+ledger+` WHERE version = ?`, m.Version).Scan(&seen); qerr {
	case nil:
		_, err = conn.ExecContext(ctx, `COMMIT`)
		return err
	case sql.ErrNoRows:
	default:
		return qerr
	}
	if _, err = conn.ExecContext(ctx, m.SQL); err != nil {
		return err
	}
	if _, err = conn.ExecContext(ctx, `INSERT INTO `+ledger+` (version, applied_at) VALUES (?, ?)`,
		m.Version, toMicro(time.Now())); err != nil {
		return err
	}
	_, err = conn.ExecContext(ctx, `COMMIT`)
	return err
}
