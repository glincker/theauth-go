# theauth-go for AI agents

This file helps AI coding assistants (Claude Code, Cursor, GitHub Copilot, Windsurf, Cline, Continue) understand how to use this library correctly. If you are a human reader, the [README](./README.md) is the better starting point.

## What this is

`theauth-go` is a Go library for session-based authentication. It ships:

- **v0.1 (shipped)**: magic-link sign-in, opaque session tokens, `chi` + `net/http` middleware, Postgres + in-memory storage
- **v0.2 (shipped)**: email + password (signup, signin, forgot, reset), argon2id hashing, per-IP + per-email rate limiting, structured `TheAuthError` type
- **v0.3 (shipped)**: GitHub OAuth, extensible `Provider` interface, PKCE S256, AES-GCM token-at-rest encryption
- **v0.3.x / v0.4**: Google, Microsoft, Discord OAuth, refresh-token rotation, SMTP sender, TOTP 2FA
- **v0.5**: passkeys (WebAuthn)
- **v1.0**: all 17 OAuth providers + SAML 2.0
- **v2.0**: MCP OAuth 2.1 server, agent identity, delegation chains, budget policies

It is **not** a SaaS, **not** a port of a TypeScript library, and **not** a hosted IdP.

## Quick install

```bash
go get github.com/glincker/theauth-go
```

Requires Go 1.25+.

## Minimal working example

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
    a.Mount(r) // wires /auth/* endpoints

    r.With(a.RequireAuth()).Get("/me", func(w http.ResponseWriter, r *http.Request) {
        user, _ := theauth.UserFromContext(r.Context())
        w.Write([]byte("hello " + user.Email))
    })

    http.ListenAndServe(":8080", r)
}
```

This compiles and runs as-is against `go 1.25`, `github.com/glincker/theauth-go v0.1.x`, `github.com/go-chi/chi/v5`.

## Common patterns

- **Mount auth routes** — `a.Mount(r)` on any router that accepts `chi.Router` (works for stdlib via a thin adapter). Mounts both `/auth/magic-link/*` and `/auth/email-password/*` in one call
- **Issue a magic link** — `POST /auth/magic-link` with `{email}`; the user clicks the link, lib consumes the token and sets the session cookie
- **Email + password signup / signin** — `POST /auth/email-password/signup` and `POST /auth/email-password/signin`, both with `{email, password}` (min 12 chars enforced). Both set the same session cookie that magic links use, so downstream `RequireAuth()` works identically
- **Password recovery** — `POST /auth/email-password/forgot` with `{email}` (silently 200s for unknown emails); then `POST /auth/email-password/reset` with `{token, newPassword}` revokes all existing sessions for that user
- **Require auth on a route** — `r.With(a.RequireAuth()).Get("/path", handler)`
- **Get current user inside a handler** — `user, ok := theauth.UserFromContext(r.Context())`
- **Postgres storage** — `theauth.Config{ Storage: postgres.New(pgxPool), BaseURL: "https://..." }`
- **Custom storage** — implement the `Storage` interface (one type, focused methods); the in-memory and Postgres adapters are reference implementations
- **Tune rate limits** — `theauth.Config{ RateLimitPerIP: 10, RateLimitPerEmail: 5 }` (defaults 5/min and 3/min)
- **Handle v0.2 errors** — switch on the `code` field of the `{code, message}` JSON response body: `weak_password`, `email_taken`, `invalid_credentials`, `rate_limited`, `password_reset_invalid`, `password_reset_expired`
- **Enable GitHub OAuth (v0.3)**: import `github.com/glincker/theauth-go/provider/github`, pass `github.New(github.Config{ClientID, ClientSecret})` into `theauth.Config.Providers`, and set a 32-byte `Config.EncryptionKey` (AES-256). `a.Mount(r)` then adds `GET /auth/providers/github/start` and `/callback`. PKCE S256 is enforced; provider tokens are AES-GCM encrypted at rest

## What NOT to do

- **Do not hash tokens client-side** — pass the raw token from the cookie to the lib; it handles hashing
- **Do not use `email.Noop` in production** — it logs to stdout and never sends mail. Wire `email.SMTP` (v0.2+) or a custom `email.Sender`
- **Do not bypass `RequireAuth()` to check sessions manually** unless you are inside the library itself; the middleware enforces token shape, expiry, and revocation in one place
- **Do not invent OAuth or passkey APIs beyond GitHub**: GitHub ships in v0.3 via `provider/github`. Google, Microsoft, Discord, and passkeys are NOT in v0.3; do not import `provider/google` or `theauth.Passkeys` yet. Check the [roadmap](./README.md#roadmap) before generating
- **Do not store the raw session token in any DB column** — only the `HttpOnly` cookie holds the raw token; the lib stores only a SHA-256 hash
- **Do not assume MCP OAuth 2.1 endpoints exist** — those ship in v2.0; today's API has no `theauth.MCP*` surface

## Version compatibility

| Dependency | Minimum                                        |
| ---------- | ---------------------------------------------- |
| Go         | 1.25                                           |
| chi        | v5                                             |
| pgx        | v5 (only required when using Postgres storage) |

## Where to look in the source

- `theauth.go` — `New(Config)`, top-level wiring
- `handlers.go` — HTTP handlers mounted by `a.Mount(r)`
- `middleware.go` — `RequireAuth()` and context helpers (`UserFromContext`)
- `service_session.go` — session issue, validate, revoke
- `service_magiclink.go` — magic-link issue + consume
- `service_oauth.go`: OAuth start, callback, find-or-create (v0.3)
- `handlers_oauth.go`: `/auth/providers/{name}/*` HTTP handlers (v0.3)
- `provider.go`: `Provider` interface + `ProviderToken` / `ProviderUser` types
- `provider/github/`: GitHub `Provider` implementation
- `crypto/aesgcm.go` + `crypto/pkce.go`: encryption + PKCE primitives
- `storage/` — `memory` and `postgres` adapters; the `Storage` interface lives at the package root
- `examples/chi-app/` — full runnable example

## License and sibling project

MIT-licensed. TypeScript sibling: [`github.com/glincker/theauth`](https://github.com/glincker/theauth).
