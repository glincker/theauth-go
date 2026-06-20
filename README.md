# TheAuth — Go

> The auth library for AI agents and the humans who run them.

Session-based auth for Go with magic links, opaque tokens, and chi middleware. Postgres + in-memory storage. Designed to ship.

🚧 **v0.2 pre-release.** Email + password done (v0.2). OAuth providers next (v0.3), TOTP/passkeys (v0.4+), MCP OAuth 2.1 (v2.0).

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

## Email + password (v0.2)

Mounting `a.Mount(r)` also wires up the `/auth/email-password` route group:

| Method + path                                | Body                              | Notes                                            |
| -------------------------------------------- | --------------------------------- | ------------------------------------------------ |
| `POST /auth/email-password/signup`           | `{email, password}`               | Creates user, sets session cookie, sends verify  |
| `POST /auth/email-password/signin`           | `{email, password}`               | Sets session cookie                              |
| `POST /auth/email-password/forgot`           | `{email}`                         | Silently 200 even for unknown emails             |
| `POST /auth/email-password/reset`            | `{token, newPassword}`            | Revokes all of the user's existing sessions     |

Client-side example:

```js
await fetch("/auth/email-password/signup", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ email: "you@example.com", password: "min-12-chars" }),
});
// Cookie is set on the response — subsequent requests carry it automatically.
```

Built-in safeguards:

- **Argon2id hashing** (OWASP 2026 defaults: 64 MiB / 3 iters / 4 threads)
- **Minimum 12-char password** enforced in service layer (NIST 2024 baseline)
- **Per-IP rate limit** (5/min default) on every credential endpoint
- **Per-email rate limit** (3/min default) on signin + forgot
- **Anti-enumeration**: unknown email and wrong password return the same `invalid_credentials` code; `/forgot` silently 200s for unknown emails
- **Soft email verification**: signup issues a session immediately; the verify magic link is sent but signin does not block on `user.emailVerifiedAt` — gate sensitive features on the client side by checking `/auth/me`'s `emailVerifiedAt`

Rate limits are configurable:

```go
theauth.New(theauth.Config{
    RateLimitPerIP:    10,  // default 5
    RateLimitPerEmail: 5,   // default 3
    // ...
})
```

Error responses on v0.2 endpoints use a stable `{code, message}` JSON shape — switch on `code`:

| Code                       | HTTP  | When                                       |
| -------------------------- | ----- | ------------------------------------------ |
| `weak_password`            | 400   | password < 12 chars                        |
| `email_taken`              | 409   | signup with existing email                 |
| `invalid_credentials`      | 401   | wrong password OR unknown email at signin  |
| `rate_limited`             | 429   | per-IP or per-email cap hit                |
| `password_reset_invalid`   | 401   | reset token unknown or already used        |
| `password_reset_expired`   | 401   | reset token past its TTL                   |

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
- `email.SMTP` — minimal SMTP (set host, port, from) — *coming v0.3*

Custom: implement `email.Sender`.

## Roadmap

- **v0.1** ✅ Magic links, sessions, chi middleware, Postgres + in-memory
- **v0.2** ✅ Email + password (signup, signin, forgot, reset), argon2id, per-IP + per-email rate limiting, structured `TheAuthError` type
- **v0.3** — GitHub OAuth (provider interface), refresh-token rotation, SMTP email sender
- **v0.4** — Google + Discord + Microsoft OAuth, TOTP 2FA
- **v0.5** — WebAuthn / passkeys
- **v1.0** — All 17 OAuth providers + SAML
- **v2.0** — MCP OAuth 2.1 server + agent identity + delegation chains

## Sibling project

[`github.com/glincker/theauth`](https://github.com/glincker/theauth) — TypeScript implementation (formerly `kavachos`, rebranded 2026-06).

## License

MIT.
