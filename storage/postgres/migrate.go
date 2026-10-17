// Package postgres: migrate.go applies the embedded SQL migrations at boot, before theauth.New.
// Migrate is safe across replicas (transaction-scoped advisory lock) and reruns are no-ops.
package postgres

import (
	"context"
	"embed"
	"fmt"
	"hash/fnv"
	"io/fs"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.up.sql
var migrationsFS embed.FS

const (
	migrationsDir      = "migrations"
	migrationsLedger   = "theauth_schema_migrations"
	migrationsLockName = "theauth-go.migrate"
)

// Migrate applies embedded up migrations not yet in theauth_schema_migrations, in version order,
// under a transaction-scoped advisory lock. Call it before theauth.New.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	files, err := loadMigrationFiles()
	if err != nil {
		return fmt.Errorf("theauth migrate: load embedded migrations: %w", err)
	}
	return pgx.BeginTxFunc(ctx, pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		lockKey := advisoryLockKey(migrationsLockName)
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, lockKey); err != nil {
			return fmt.Errorf("acquire advisory lock: %w", err)
		}

		if _, err := tx.Exec(ctx, fmt.Sprintf(
			`CREATE TABLE IF NOT EXISTS %s (
				version    text PRIMARY KEY,
				applied_at timestamptz NOT NULL DEFAULT now()
			)`, migrationsLedger,
		)); err != nil {
			return fmt.Errorf("ensure ledger table: %w", err)
		}

		applied, err := loadAppliedVersions(ctx, tx)
		if err != nil {
			return fmt.Errorf("load applied versions: %w", err)
		}

		for _, f := range files {
			if _, ok := applied[f.version]; ok {
				continue
			}
			if _, err := tx.Exec(ctx, f.body); err != nil {
				return fmt.Errorf("apply migration %s: %w", f.version, err)
			}
			if _, err := tx.Exec(ctx,
				fmt.Sprintf(`INSERT INTO %s (version) VALUES ($1) ON CONFLICT DO NOTHING`, migrationsLedger),
				f.version,
			); err != nil {
				return fmt.Errorf("record migration %s: %w", f.version, err)
			}
		}
		return nil
	})
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

func loadAppliedVersions(ctx context.Context, tx pgx.Tx) (map[string]struct{}, error) {
	rows, err := tx.Query(ctx, fmt.Sprintf(`SELECT version FROM %s`, migrationsLedger))
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

func advisoryLockKey(name string) int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(name))
	return int64(h.Sum64())
}
