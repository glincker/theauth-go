# Installation

## Requirements

- **Go 1.25+**
- A `chi` or `net/http`-compatible HTTP router (the library works with any; chi is used in examples).

## Install the main module

```bash
go get github.com/glincker/theauth-go
```

This installs the full theauth-go surface: magic links, email/password, WebAuthn, TOTP, SAML, SCIM, RBAC, audit, and the OAuth 2.1 authorization server.

## Install only the MCP resource server SDK

If you are building an MCP resource server and only need JWT validation (not the auth server itself), install the zero-dependency submodule instead:

```bash
go get github.com/glincker/theauth-go/mcpresource
```

`mcpresource` has no third-party dependencies. Importing it does not pull in theauth core or any storage adapter.

## Postgres storage adapter

The Postgres adapter uses `pgx/v5` and generated SQL via `sqlc`. It is bundled in the main module under `storage/postgres`; no separate `go get` is needed. You do need to run migrations before first use:

```go
import "github.com/glincker/theauth-go/storage/postgres"

pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
store, err := postgres.New(pool)
// Migrations are embedded; call store.Migrate(ctx) or run them from storage/postgres/migrations/
```

## Verify the installation

```bash
go build ./...
go test github.com/glincker/theauth-go/... -count=1 -short
```

## Release verification

Every release artifact is signed with `cosign` keyless signing (Sigstore OIDC). See [Releases and Verification](../security/releases.md) for the smoke-test commands.
