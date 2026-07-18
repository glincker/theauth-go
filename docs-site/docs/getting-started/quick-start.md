# Quick Start

This walks through the smallest working theauth-go server: an in-memory store, magic links, and email/password sign-in, wired to a chi router in a handful of lines.

## Minimal server (magic links + email/password)

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

Run it:

```bash
go run main.go
```

Sign up:

```bash
curl -s -X POST http://localhost:8080/auth/email-password/signup \
  -H "Content-Type: application/json" \
  -d '{"email":"you@example.com","password":"supersecret123"}'
```

Or request a magic link:

```bash
curl -s -X POST http://localhost:8080/auth/magic-link \
  -H "Content-Type: application/json" \
  -d '{"email":"you@example.com"}'
```

## Add Postgres storage

Replace `memory.New()` with the Postgres adapter for persistent sessions:

```go
import (
    "github.com/jackc/pgx/v5/pgxpool"
    "github.com/glincker/theauth-go/storage/postgres"
)

pool, _ := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
a, _ := theauth.New(theauth.Config{
    Storage: postgres.New(pool),
    BaseURL: "https://myapp.com",
})
```

## Mounted endpoints

`a.Mount(r)` wires the following routes:

| Endpoint | Purpose |
|---|---|
| `POST /auth/magic-link` | Request a sign-in link |
| `GET /auth/magic-link/verify` | Consume the link token, issue session |
| `POST /auth/email-password/signup` | Register, sets session cookie |
| `POST /auth/email-password/signin` | Sign in, sets session cookie |
| `POST /auth/email-password/forgot` | Request a password reset (silently 200 for unknown emails) |
| `POST /auth/email-password/reset` | Consume reset token, revoke all sessions |
| `GET /auth/me` | Current user (requires auth) |
| `DELETE /auth/sessions/current` | Sign out |

OAuth providers (`GET /auth/providers/{name}/start` and `/callback`): 12 built-in providers, including github, google, microsoft, discord, apple, facebook, slack, gitlab, bitbucket, twitch, linkedin, and x. See [Add an OAuth Provider](../guides/add-oauth-provider.md) for the full list.

WebAuthn: `/auth/webauthn/register/{begin,finish}`, `/auth/webauthn/login/{begin,finish}`, `/auth/webauthn/credentials`.

TOTP: `/auth/totp/enroll/{begin,finish}`, `/auth/totp/verify`, `/auth/totp/recovery`, `DELETE /auth/totp`.

## Next steps

- [Storage Backends](storage-backends.md) - Memory vs Postgres, migration strategy.
- [Add an OAuth Provider](../guides/add-oauth-provider.md) - Wire GitHub, Google, Microsoft, or Discord.
- [Enable WebAuthn Passkeys](../guides/webauthn-passkeys.md) - Passkey registration and discoverable login.
- [Configuration Reference](../reference/configuration.md) - Full `theauth.Config` shape.
