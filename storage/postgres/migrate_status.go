package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// MigrationStatus describes one embedded migration and whether the ledger has it.
type MigrationStatus struct {
	// Version is the migration id, for example "0001_init".
	Version string
	// Applied reports whether the version is recorded in theauth_schema_migrations.
	Applied bool
	// AppliedAt is the ledger timestamp; zero when not applied.
	AppliedAt time.Time
	// SQL is the embedded up migration body.
	SQL string
}

// Status lists every embedded migration in version order with its ledger state. It is read
// only: it never creates the ledger table and takes no lock. A missing ledger means every
// migration is pending. Ledger versions unknown to this build are ignored.
func Status(ctx context.Context, pool *pgxpool.Pool) ([]MigrationStatus, error) {
	files, err := loadMigrationFiles()
	if err != nil {
		return nil, fmt.Errorf("theauth migrate status: load embedded migrations: %w", err)
	}
	var exists bool
	if err := pool.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, migrationsLedger).Scan(&exists); err != nil {
		return nil, fmt.Errorf("theauth migrate status: probe ledger: %w", err)
	}
	applied := map[string]time.Time{}
	if exists {
		rows, err := pool.Query(ctx, fmt.Sprintf(`SELECT version, applied_at FROM %s`, migrationsLedger))
		if err != nil {
			return nil, fmt.Errorf("theauth migrate status: read ledger: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var v string
			var at time.Time
			if err := rows.Scan(&v, &at); err != nil {
				return nil, fmt.Errorf("theauth migrate status: scan ledger: %w", err)
			}
			applied[v] = at
		}
		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("theauth migrate status: read ledger: %w", err)
		}
	}
	out := make([]MigrationStatus, 0, len(files))
	for _, f := range files {
		at, ok := applied[f.version]
		out = append(out, MigrationStatus{Version: f.version, Applied: ok, AppliedAt: at, SQL: f.body})
	}
	return out, nil
}
