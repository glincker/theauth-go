package mysql

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// MigrationStatus describes one embedded migration and whether the ledger has it.
type MigrationStatus struct {
	// Version is the migration id, for example "0001_init".
	Version string
	// Applied reports whether the version is recorded in theauth_schema_migrations.
	Applied bool
	// AppliedAt is the ledger timestamp (UTC when the DSN has no loc); zero when not applied or
	// when the driver returned a value that could not be parsed.
	AppliedAt time.Time
	// SQL is the embedded up migration body.
	SQL string
}

// Status lists every embedded migration in version order with its ledger state. It is read
// only: it never creates the ledger table and takes no lock. A missing ledger means every
// migration is pending. Ledger versions unknown to this build are ignored.
func Status(ctx context.Context, db *sql.DB) ([]MigrationStatus, error) {
	files, err := loadMigrationFiles()
	if err != nil {
		return nil, fmt.Errorf("theauth mysql migrate status: load embedded migrations: %w", err)
	}
	var n int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = ?`,
		migrationsLedger).Scan(&n); err != nil {
		return nil, fmt.Errorf("theauth mysql migrate status: probe ledger: %w", err)
	}
	applied := map[string]time.Time{}
	if n > 0 {
		// migrationsLedger is a package constant, not input.
		rows, err := db.QueryContext(ctx, `SELECT version, applied_at FROM `+migrationsLedger)
		if err != nil {
			return nil, fmt.Errorf("theauth mysql migrate status: read ledger: %w", err)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var v string
			var raw any
			if err := rows.Scan(&v, &raw); err != nil {
				return nil, fmt.Errorf("theauth mysql migrate status: scan ledger: %w", err)
			}
			applied[v] = parseLedgerTime(raw)
		}
		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("theauth mysql migrate status: read ledger: %w", err)
		}
	}
	out := make([]MigrationStatus, 0, len(files))
	for _, f := range files {
		at, ok := applied[f.version]
		out = append(out, MigrationStatus{Version: f.version, Applied: ok, AppliedAt: at, SQL: f.body})
	}
	return out, nil
}

// parseLedgerTime accepts time.Time (parseTime=true) or the raw DATETIME text.
func parseLedgerTime(raw any) time.Time {
	switch v := raw.(type) {
	case time.Time:
		return v
	case []byte:
		return parseLedgerTime(string(v))
	case string:
		for _, layout := range []string{"2006-01-02 15:04:05.999999", "2006-01-02 15:04:05"} {
			if t, err := time.ParseInLocation(layout, v, time.UTC); err == nil {
				return t
			}
		}
	}
	return time.Time{}
}
