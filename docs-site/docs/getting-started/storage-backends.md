# Storage Backends

theauth-go ships two built-in storage adapters. Both implement the same `Storage` interface, so you can switch between them by changing a single constructor argument.

## In-memory (`storage/memory`)

```go
import "github.com/glincker/theauth-go/storage/memory"

store := memory.New()
```

- **Zero external dependencies.** No database process needed.
- **Not persistent.** All data is lost when the process restarts.
- **Use for:** local development, integration tests, quick demos.

## Postgres (`storage/postgres`)

```go
import (
    "github.com/jackc/pgx/v5/pgxpool"
    "github.com/glincker/theauth-go/storage/postgres"
)

pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
if err != nil {
    log.Fatal(err)
}
store := postgres.New(pool)
```

- **Production-ready.** Persistent, concurrent, supports all theauth features.
- **Dependencies:** `pgx/v5`. Generated SQL from `sqlc`.
- **Migrations:** Embedded under `storage/postgres/migrations/`. They are append-only: columns and tables are added, never renamed destructively.

### Running migrations

The store does not auto-migrate. Run migrations yourself at startup or via a CI step:

```go
// If the postgres.Store exposes a Migrate method, call it:
if err := store.Migrate(ctx); err != nil {
    log.Fatal(err)
}
```

Or apply the SQL files directly:

```bash
psql "$DATABASE_URL" -f storage/postgres/migrations/0001_users.up.sql
# ... repeat for each migration in order
```

## The `Storage` interface

Both adapters satisfy `theauth.Storage`. The interface is the only surface a custom backend needs to implement. See [Storage Interface Reference](../reference/storage.md) for the full contract.

## Special rules

- Adding a method to `Storage` is a breaking change. New persistence operations land behind optional interfaces (e.g., `OAuthServerStorage`) detected at runtime via type assertion.
- The Postgres adapter's migrations directory is append-only. A renamed column ships as a new migration that adds the new column and removes the old one in a later release. This protects rolling-restart deployments.

## Choosing a backend

| Situation | Backend |
|---|---|
| Local dev, CI | `memory` |
| Production (single node or replicated Postgres) | `postgres` |
| Custom database (MySQL, SQLite, etc.) | Implement `Storage`; see [Write a Custom Storage Backend](../guides/custom-storage-backend.md) |
