package main

import (
	"fmt"

	"github.com/glincker/theauth-go/cmd/theauth-migrate/internal"
	"github.com/glincker/theauth-go/storage/memory"
)

// openStorage returns an internal.Storage implementation for the chosen
// backend. Currently "memory" is supported for testing. "postgres" emits
// a clear error directing the operator to supply a DSN.
func openStorage(backend, dsn string) (internal.Storage, error) {
	switch backend {
	case "memory":
		return memory.New(), nil
	case "postgres":
		if dsn == "" {
			return nil, fmt.Errorf("--dsn is required for --storage postgres")
		}
		// Postgres support requires importing storage/postgres, which pulls in
		// pgx. The CLI binary does not currently link pgx to keep the binary
		// lightweight and avoid the C dependency for operators who only need
		// the export step. The apply-to-postgres path is available by calling
		// internal.ApplyBundle directly from your own Go code with a
		// *postgres.Store, or by using a future build tag.
		return nil, fmt.Errorf(
			"postgres storage is not yet linked in this build; " +
				"run the export step (--export) first, inspect the bundle, " +
				"then use --storage memory for a dry-run or wire internal.ApplyBundle " +
				"directly with a postgres.Store",
		)
	default:
		return nil, fmt.Errorf("unknown storage backend %q; choose memory or postgres", backend)
	}
}
