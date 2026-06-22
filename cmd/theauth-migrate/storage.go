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
		// Postgres support requires importing storage/postgres, which pulls
		// in pgx. The CLI binary does not link pgx today to keep the binary
		// lightweight. Operators who want apply-to-postgres should call
		// internal.ApplyBundle directly from their own Go code with a
		// *postgres.Store, or wait for a future build-tag opt-in.
		return nil, fmt.Errorf(
			"postgres storage is not linked in this build, run the export step " +
				"first and wire internal.ApplyBundle with a postgres.Store from " +
				"your own Go code",
		)
	default:
		return nil, fmt.Errorf("unknown storage backend %q; choose memory or postgres", backend)
	}
}
