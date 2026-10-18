# theauth-go CLI and OpenAPI

```
go install github.com/glincker/theauth-go/v2/cmd/theauth-go@latest
```

| Command | Purpose |
|---|---|
| `theauth-go secret` | Print random key material. Flags: `--bytes` (16 to 128, default 32), `--format base64url\|hex\|env`, `--name` for the env format |
| `theauth-go openapi` | Print an OpenAPI 3.1 document for the default route set. Flags: `--base-url`, `--title`, `--version`, `--out` |
| `theauth-go db status` | List applied and pending migrations. Flags: `--driver postgres\|mysql`, `--dsn` (or `$THEAUTH_DATABASE_URL`), `--json`, `--exit-code` |
| `theauth-go db migrate` | Apply pending migrations through the backend's own `Migrate`. Flags: `--driver`, `--dsn`, `--dry-run` (print the pending SQL), `--json` |
| `theauth-go init` | Scaffold `main.go` and `.env.example`. Flags: `--dir`, `--storage memory\|postgres\|mysql`, `--print`, `--force`, `--with-postgres` |
| `theauth-go policy test <suite.json>` | Run a policy test suite and print failures with their explanation. Exit 1 on failure. See [policy-explain.md](policy-explain.md) |

## Database migrations

```
theauth-go db status  --driver postgres --dsn "postgres://user:pass@localhost:5432/theauth"
theauth-go db status  --driver mysql --json --exit-code     # DSN from $THEAUTH_DATABASE_URL
theauth-go db migrate --driver postgres --dry-run           # print the SQL, run nothing
theauth-go db migrate --driver postgres
```

Status prints the id, name and applied time of each embedded migration from the `theauth_schema_migrations` ledger, then a count. `--json` output has stable keys: `driver`, `applied`, `pending` and a `migrations` array of `version`, `id`, `name`, `applied`, `applied_at` (null when pending). Status is read only: it does not create the ledger and takes no lock. `db migrate` calls the same `Migrate` your application would run (advisory lock), so replicas can run it safely.

Passwords in a DSN are never printed: connection errors show the DSN with the password replaced by `xxxxx`.

Exit codes: `0` success, `1` an error, or pending migrations with `status --exit-code`, `2` usage error.

Limits:

- **sqlite is library only.** `storage/sqlite` is a separate module that depends on the root module, so the CLI (in the root module) cannot import it. Call `sqlite.Migrate(ctx, db)` from your own code, or `sqlite.RenderMigrations` to inspect the SQL.
- **`--to <id>` is rejected.** The backends apply every pending migration in order and expose no target. Use `--dry-run` to review first.
- **No dirty or locked state.** The ledger records only applied versions, so there is no dirty flag to report. Postgres runs all pending migrations in one transaction. MySQL DDL is not transactional: if a migration fails midway, fix the schema by hand before rerunning.

## Scaffolding a project

```
mkdir myapp && cd myapp && go mod init example.com/myapp
theauth-go init --storage postgres --with-postgres
go get github.com/glincker/theauth-go/v2@latest && go mod tidy
```

`init` writes `main.go` (theauth.New with the chosen storage and `Bootstrap` gating the first signup behind `THEAUTH_SETUP_TOKEN`), `.env.example` with a generated encryption key and setup token (mode 0600), and with `--with-postgres` a `docker-compose.yml` postgres service plus a matching password and URL. It makes no network calls and never runs `go get`: the command is printed. Existing files are skipped unless `--force`. `--print` writes `main.go` to stdout and touches nothing. A missing `go.mod` is reported with the `go mod init` command to run.

Related binaries: `theauth-doctor` fetches the security report of a running server, and `theauth-migrate` imports users from Auth0 and Cognito.

## Generating OpenAPI from your own router

The CLI documents the default routes. To describe the routes your application actually mounts (optional features included), call the library from your own code:

```go
r := chi.NewRouter()
auth.Mount(r)

doc, err := openapi.Generate(r, openapi.Info{
	Title:     "My API",
	Version:   "1.0.0",
	ServerURL: "https://auth.example.com",
})
```

Routes are read with `chi.Walk`, so the document cannot drift from what is mounted. Well-known auth routes get summaries, tags and security requirements (session cookie or bearer). Other routes are listed with a generated summary and operation id. Request and response bodies are described as generic objects; the document is meant for client discovery and gateways, not for full schema generation.
