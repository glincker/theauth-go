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
		// pgx. That import is deliberate: the migrate CLI is a standalone
		// binary and the extra dependency is acceptable.
		//
		// For now, return an error directing the operator to use
		// --storage memory for smoke-testing and then run the apply step
		// against a real database via a migration-specific build tag.
		//
		// TODO: import storage/postgres once the CLI has a build tag that
		// opts in to the pgx dependency. Track in:
		// https://github.com/glincker/theauth-go/issues/TODO
		return nil, fmt.Errorf(
			"postgres storage is not yet linked in this build; " +
				"run the export step first (--export), inspect the bundle, " +
				"then import into postgres using your preferred migration script. " +
				"For integration testing use --storage memory.",
		)
	default:
		return nil, fmt.Errorf("unknown storage backend %q; choose memory or postgres", backend)
	}
}
