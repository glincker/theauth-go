# Storage Interface

The `theauth.Storage` interface is the single surface a custom backend must implement. Both built-in adapters (`storage/memory` and `storage/postgres`) satisfy it.

## Stability guarantee

The base `Storage` interface is frozen at v1.0. Adding a method to it is a v2.0 breaking change. New persistence operations land behind optional extension interfaces (e.g., `OAuthServerStorage`) that the library detects via type assertion at `theauth.New` time.

## In-tree adapters

| Package | Use case |
|---|---|
| `github.com/glincker/theauth-go/storage/memory` | Local dev, testing |
| `github.com/glincker/theauth-go/storage/postgres` | Production (`pgx/v5` + `sqlc`) |

Both expose `New(...)` constructors that return a `*Store` satisfying `theauth.Storage`.

## Extension interface: `OAuthServerStorage`

When `Config.AuthorizationServer` is set, the storage adapter must also satisfy `OAuthServerStorage`. This interface adds methods for OAuth clients, authorization codes, refresh tokens, JWKS keys, agents, and delegation grants.

Both in-tree adapters satisfy `OAuthServerStorage` when the OAuth 2.1 AS migrations have been applied.

## Conformance suite

Use `github.com/glincker/theauth-go/storagetest` to verify a custom adapter:

```go
func TestConformance(t *testing.T) {
    storagetest.Run(t, func() theauth.Storage {
        return mystorage.New()
    })
}
```

## Interface documentation

Full godoc is available at [pkg.go.dev/github.com/glincker/theauth-go#Storage](https://pkg.go.dev/github.com/glincker/theauth-go#Storage).

## Special rules

### Append-only migrations

The `storage/postgres/migrations/` directory is append-only. Columns are added via new migrations; they are never renamed destructively. This protects rolling-restart deployments.

### Audit table append-only

The `audit_events` table is append-only by contract. Adapters MUST NOT expose `UPDATE` or `DELETE` for audit rows. The `Storage` interface deliberately offers only `InsertAuditEvents` and `QueryAuditEvents`. Operators wanting tamper-evidence should layer Merkle signing on top.

### `ErrNotFound`

On lookup misses, adapters MUST return `theauth.ErrStorageNotFound` (re-exported from `storage.ErrNotFound`). The service layer uses `errors.Is` checks against this sentinel to distinguish "row missing" from other errors.

## Write a custom adapter

See [Write a Custom Storage Backend](../guides/custom-storage-backend.md) for the step-by-step guide, including how to run the conformance suite.
