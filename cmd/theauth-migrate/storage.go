package main

import (
	"fmt"

	"github.com/glincker/theauth-go/v2/cmd/theauth-migrate/internal"
	"github.com/glincker/theauth-go/v2/storage/memory"
)

// openStorage returns the storage for the chosen backend. Only "memory" is supported here;
// "postgres" needs a DSN.
func openStorage(backend, dsn string) (internal.Storage, error) {
	switch backend {
	case "memory":
		return memory.New(), nil
	case "postgres":
		if dsn == "" {
			return nil, fmt.Errorf("--dsn is required for --storage postgres")
		}
		// Postgres is not linked into this binary, to keep it lightweight. Apply to Postgres from Go code
		// with a *postgres.Store.
		return nil, fmt.Errorf(
			"postgres storage is not linked in this build, run the export step " +
				"first and wire internal.ApplyBundle with a postgres.Store from " +
				"your own Go code",
		)
	default:
		return nil, fmt.Errorf("unknown storage backend %q; choose memory or postgres", backend)
	}
}
