# theauth-go

> A modern auth library for Go. Magic links, sessions, OAuth, MCP OAuth 2.1. Drop-in chi/net/http middleware. Postgres or in-memory storage.

[![Go Reference](https://pkg.go.dev/badge/github.com/glincker/theauth-go.svg)](https://pkg.go.dev/github.com/glincker/theauth-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/glincker/theauth-go)](https://goreportcard.com/report/github.com/glincker/theauth-go)
[![CI](https://github.com/glincker/theauth-go/actions/workflows/ci.yml/badge.svg)](https://github.com/glincker/theauth-go/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/glincker/theauth-go)](https://github.com/glincker/theauth-go/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

`theauth-go` is a small, opinionated Go auth library. Sign in with email magic links today; email + password, OAuth, passkeys, and an MCP OAuth 2.1 server land on the published roadmap below.

It is built to drop into a `chi` or `net/http` server in under twenty lines, store sessions in Postgres or memory, and grow into agent identity (the part of auth most libraries skip) without a rewrite.

---

## Why theauth-go

**Who it's for**

- Go developers building web apps or APIs who want a real auth flow without owning every line of it
- Teams building MCP servers and AI-agent backends who need agent identity, not just human login
- Anyone who would otherwise reach for a SaaS auth vendor and would rather self-host

**What's different**

- **Go-native**: idiomatic `net/http` handlers, a tiny `Storage` interface, `chi`-friendly middleware. Not a port of a TypeScript library
- **Agent identity on the roadmap**: MCP OAuth 2.1 server, delegation chains, and budget policies are first-class plans (v2.0) — not bolted on
- **Self-hosted forever**: MIT-licensed library, no per-MAU pricing, no vendor lock-in, your DB

**What it isn't**

- Not a SaaS (no hosted dashboard, no managed UI)
- Not for Node — see the TypeScript sibling [`glincker/theauth`](https://github.com/glincker/theauth)
- Not a full IdP yet — OAuth providers ship in v0.3, SAML in v1.0

---

## Install

```bash
go get github.com/glincker/theauth-go
```

Requires **Go 1.25+** (matches `pgx/v5`).

---

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
    a.Mount(r) // wires /auth/* endpoints (magic-link, me, signout, ...)

    r.With(a.RequireAuth()).Get("/me", func(w http.ResponseWriter, r *http.Request) {
        user, _ := theauth.UserFromContext(r.Context())
        w.Write([]byte("hello " + user.Email))
    })

    http.ListenAndServe(":8080", r)
}
```

Full runnable example: [`examples/chi-app/`](./examples/chi-app).

---

## Comparison

How `theauth-go` stacks up against the libraries and services you would actually consider in 2026:

| Feature                       | theauth-go    | better-auth   | Auth0 SDK    | Stytch       | Ory Kratos    |
| ----------------------------- | ------------- | ------------- | ------------ | ------------ | ------------- |
| Language                      | Go            | TypeScript    | Multiple     | Multiple     | Go            |
| Magic links                   | Shipping      | Shipping      | Shipping     | Shipping     | Shipping      |
| Email / password              | Roadmap v0.2  | Shipping      | Shipping     | Shipping     | Shipping      |
| OAuth providers               | Roadmap v0.3  | 17            | 30+          | 20+          | 10+           |
| Passkeys / WebAuthn           | Roadmap v0.4  | Shipping      | Shipping     | Shipping     | Shipping      |
| Self-hosted                   | Yes           | Yes           | No           | No           | Yes           |
| MCP OAuth 2.1 server          | Roadmap v2.0  | Roadmap v2.0  | No           | No           | No            |
| Agent identity + delegation   | Roadmap v2.0  | Roadmap v2.0  | No           | No           | No            |
| Hosting model                 | Library       | Library       | SaaS         | SaaS         | Service       |
| Cost                          | Free (MIT)    | Free (MIT)    | Paid         | Paid         | Free (Apache) |

Honest legend: **Shipping** = available today, **Roadmap vX** = planned for that version, **No** = not planned. Numbers reflect each vendor's 2026 documentation.

---

## Architecture

```
                ┌──────────────────────────────┐
   HTTP req ─►  │  chi / net/http router       │
                │   ├── a.Mount(r)             │  /auth/* handlers
                │   └── a.RequireAuth()        │  middleware
                └──────────────┬───────────────┘
                               │
                ┌──────────────▼───────────────┐
                │  theauth core                │
                │   ├── magic-link service     │
                │   ├── session service        │  opaque tokens, hashed in DB
                │   ├── password service       │  (v0.2)
                │   └── oauth / MCP / agents   │  (v0.3 → v2.0)
                └──────────────┬───────────────┘
                               │
                ┌──────────────▼───────────────┐
                │  Storage interface           │  pluggable
                │   ├── storage/memory         │  tests, demos
                │   └── storage/postgres       │  pgx + sqlc
                └──────────────────────────────┘
```

Sessions are opaque tokens — the raw token lives only in the user's cookie; only a SHA-256 hash is persisted. Revocation is a single `UPDATE`. The `Storage` interface is the only surface a custom backend needs to implement.

---

## Storage backends

- **`storage/memory`** — in-memory, zero deps. Use for tests, local demos, and quickstarts
- **`storage/postgres`** — `pgx/v5` + `sqlc`-generated queries. Migrations live in [`storage/postgres/migrations/`](./storage/postgres/migrations) and run via [golang-migrate](https://github.com/golang-migrate/migrate)
- **Custom** — implement the `Storage` interface (one type, focused method set) to back theauth with anything: SQLite, MySQL, DynamoDB, your existing ORM

Postgres example:

```go
pool, _ := pgxpool.New(ctx, "postgres://...")
a, _ := theauth.New(theauth.Config{
    Storage: postgres.New(pool),
    BaseURL: "https://myapp.com",
})
```

---

## Email senders

- **`email.Noop`** — logs to stdout. Default. Good for local dev; **never ship to production**
- **`email.SMTP`** — minimal SMTP sender (host, port, from). Lands in v0.2
- **Custom** — implement `email.Sender` to wire Resend, Postmark, SES, SendGrid, etc.

---

## Roadmap

- **v0.1** — Shipping: magic links, sessions, chi middleware, Postgres + memory storage
- **v0.2** — In progress: email + password, rate limiting, typed errors, SMTP sender
- **v0.3** — Planned: OAuth providers (GitHub, Google, Microsoft, Discord)
- **v0.4** — Planned: WebAuthn / passkeys
- **v0.5** — Planned: TOTP 2FA
- **v1.0** — Planned: full OAuth provider library (17 providers) + SAML 2.0
- **v2.0** — Planned: MCP OAuth 2.1 server, agent identity, delegation chains, budget policies

Track the work in [GitHub Issues](https://github.com/glincker/theauth-go/issues) and [Releases](https://github.com/glincker/theauth-go/releases).

---

## FAQ

### Is `theauth-go` production-ready?

v0.1 ships sessions and magic links and is covered by unit + integration tests against Postgres. It is appropriate for greenfield projects and side projects today. Email + password lands in v0.2; OAuth in v0.3. If you need OAuth, passkeys, or 2FA right now, check the roadmap and pick the right version — or use one of the alternatives above and migrate later.

### Why not just use Auth0 or Clerk?

Both are excellent if you are happy paying per monthly active user and letting a third party hold your identity data. `theauth-go` exists for teams that want self-hosted, MIT-licensed, no-per-MAU-cost auth they fully control — including the code path that runs at login.

### Why not Ory Kratos?

Kratos is a separate service you run alongside your app. `theauth-go` is a library you import — same process, same DB, same deploy. Fewer moving parts, less ops burden, but you give up Kratos's UI flows and multi-language SDK. Pick Kratos if you need a polyglot stack; pick `theauth-go` if your backend is Go and you want library-grade simplicity.

### Why not better-auth?

`better-auth` is the TypeScript reference for this design. If your stack is Node/Next.js, use it (or use the sibling [`glincker/theauth`](https://github.com/glincker/theauth) TS implementation). `theauth-go` exists because the Go ecosystem deserves the same ergonomics natively, not via a Node sidecar.

### Why a new Go auth library?

No Go library today combines agent identity + MCP OAuth 2.1 + traditional human auth in a single package. `theauth-go` is built for the moment human and agent auth converge — sessions and magic links today, OAuth and passkeys in 2026, MCP OAuth 2.1 server + delegation in v2.0.

### What is MCP OAuth 2.1?

The Model Context Protocol's authorization spec — built on RFC 9728 (Protected Resource Metadata), RFC 8707 (Resource Indicators), RFC 8414 (Authorization Server Metadata), and RFC 7591 (Dynamic Client Registration). It lets AI agents authenticate to MCP servers with proper scope, audience, and delegation. v2.0 of `theauth-go` will be the Go reference implementation.

### Does it work with `net/http` only, no chi?

Yes. `chi` is recommended because middleware composition is cleaner, but `Mount` accepts anything that satisfies `http.Handler` registration, and `RequireAuth()` returns a standard `func(http.Handler) http.Handler`.

### How are sessions stored?

Sessions are opaque tokens. The raw token is set in an `HttpOnly`, `Secure`, `SameSite=Lax` cookie. The DB only stores a SHA-256 hash plus metadata (user ID, created/expires, revoked flag). Revocation is a single `UPDATE`.

---

## Contributing

- Bug reports and feature requests: [GitHub Issues](https://github.com/glincker/theauth-go/issues)
- Questions, design discussion, RFC threads: [GitHub Discussions](https://github.com/glincker/theauth-go/discussions)
- Pull requests welcome — please open an issue first for anything beyond a typo or one-file fix
- Run `go test ./...` and `go vet ./...` before pushing

## Sibling project

[`github.com/glincker/theauth`](https://github.com/glincker/theauth) — TypeScript implementation (formerly `kavachos`, rebranded 2026-06). Shares the same design language and roadmap; pick the one that matches your backend.

## License

MIT — see [LICENSE](./LICENSE).
