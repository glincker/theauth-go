# TheAuth — Go

> The auth library for AI agents and the humans who run them.

Session-based auth for Go with magic links, opaque tokens, and chi middleware. Postgres + in-memory storage. Designed to ship.

🚧 **v0.1 pre-release.** OAuth providers (v0.2), TOTP/passkeys (v0.3+), MCP OAuth 2.1 (v2.0).

## Install

```bash
go get github.com/glincker/theauth-go
```

## Quickstart

```go
package main

import (
	"net/http"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/storage/memory"
	"github.com/go-chi/chi/v5"
)

func main() {
	a, _ := theauth.New(theauth.Config{
		Storage: memory.New(),
		BaseURL: "http://localhost:8080",
	})

	r := chi.NewRouter()
	a.Mount(r) // POST /auth/magic-link, GET /auth/me, etc.

	r.With(a.RequireAuth()).Get("/secret", func(w http.ResponseWriter, r *http.Request) {
		user, _ := theauth.UserFromContext(r.Context())
		w.Write([]byte("hello " + user.Email))
	})

	http.ListenAndServe(":8080", r)
}
```

Full runnable example: [`examples/chi-app/`](./examples/chi-app).

## Storage backends

- `storage/memory` — in-memory (tests, demos)
- `storage/postgres` — pgx + sqlc-generated queries

```go
pool, _ := pgxpool.New(ctx, "postgres://...")
a, _ := theauth.New(theauth.Config{
    Storage: postgres.New(pool),
    BaseURL: "https://myapp.com",
})
```

Run migrations from `storage/postgres/migrations/` via [golang-migrate](https://github.com/golang-migrate/migrate).

## Email senders

- `email.Noop` — logs to stdout (default)
- `email.SMTP` — minimal SMTP (set host, port, from) — *coming v0.2*

Custom: implement `email.Sender`.

## Roadmap

- **v0.1** ✅ Magic links, sessions, chi middleware, Postgres + in-memory
- **v0.2** — OAuth providers (GitHub first), refresh-token rotation, SMTP email sender
- **v0.3** — Google + Discord + Microsoft OAuth, TOTP 2FA
- **v0.4** — WebAuthn / passkeys
- **v1.0** — All 17 OAuth providers + SAML
- **v2.0** — MCP OAuth 2.1 server + agent identity + delegation chains

## Sibling project

[`github.com/glincker/theauth`](https://github.com/glincker/theauth) — TypeScript implementation (formerly `kavachos`, rebranded 2026-06).

## License

MIT.
