# theauth-go

> A modern auth library for Go. Magic links, sessions, OAuth, MCP OAuth 2.1. Drop-in chi/net/http middleware. Postgres or in-memory storage.

[![Go Reference](https://pkg.go.dev/badge/github.com/glincker/theauth-go.svg)](https://pkg.go.dev/github.com/glincker/theauth-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/glincker/theauth-go)](https://goreportcard.com/report/github.com/glincker/theauth-go)
[![CI](https://github.com/glincker/theauth-go/actions/workflows/ci.yml/badge.svg)](https://github.com/glincker/theauth-go/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/glincker/theauth-go)](https://github.com/glincker/theauth-go/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

`theauth-go` is a small, opinionated Go auth library. Sign in with email magic links or email + password today; OAuth, passkeys, and an MCP OAuth 2.1 server land on the published roadmap below.

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
    a.Mount(r) // wires /auth/* endpoints (magic-link, email-password, me, signout, ...)

    r.With(a.RequireAuth()).Get("/me", func(w http.ResponseWriter, r *http.Request) {
        user, _ := theauth.UserFromContext(r.Context())
        w.Write([]byte("hello " + user.Email))
    })

    http.ListenAndServe(":8080", r)
}
```

Email + password (v0.2) calls the same mounted routes:

```go
// signup
resp, _ := http.Post("http://localhost:8080/auth/email-password/signup",
    "application/json", strings.NewReader(`{"email":"you@example.com","password":"twelve-chars-min"}`))
// signin same shape — POST /auth/email-password/signin
```

Full runnable example: [`examples/chi-app/`](./examples/chi-app).

---

## Email + password (v0.2)

Mounting `a.Mount(r)` also wires up the `/auth/email-password` route group:

| Method + path                                | Body                              | Notes                                            |
| -------------------------------------------- | --------------------------------- | ------------------------------------------------ |
| `POST /auth/email-password/signup`           | `{email, password}`               | Creates user, sets session cookie, sends verify  |
| `POST /auth/email-password/signin`           | `{email, password}`               | Sets session cookie                              |
| `POST /auth/email-password/forgot`           | `{email}`                         | Silently 200 even for unknown emails             |
| `POST /auth/email-password/reset`            | `{token, newPassword}`            | Revokes all of the user's existing sessions     |

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

---

## OAuth providers (v0.3 + v0.4)

Each provider lives in its own sub-package so consumers only pull in the
ones they want. v0.3 shipped GitHub; v0.4 adds Google, Microsoft, and
Discord. All four implement the same `theauth.Provider` interface and
mount the same `/start` + `/callback` route shape.

### GitHub (v0.3)

Register an OAuth app at https://github.com/settings/developers with a
callback of `https://yourapp.com/auth/providers/github/callback`, then
wire the provider into `theauth.New`:

```go
import (
    "github.com/glincker/theauth-go"
    "github.com/glincker/theauth-go/provider/github"
)

key := mustGetenv("THEAUTH_ENCRYPTION_KEY") // 32 raw bytes (AES-256)

a, _ := theauth.New(theauth.Config{
    Storage:       postgres.New(pool),
    BaseURL:       "https://yourapp.com",
    EncryptionKey: key,
    Providers: []theauth.Provider{
        github.New(github.Config{
            ClientID:     os.Getenv("GITHUB_CLIENT_ID"),
            ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
        }),
    },
    PostLoginRedirect: "/dashboard",
})
```

### Google (v0.4)

Register at https://console.cloud.google.com/apis/credentials, set the
authorized redirect URI to `https://yourapp.com/auth/providers/google/callback`,
then add the provider to the slice above:

```go
import "github.com/glincker/theauth-go/provider/google"

google.New(google.Config{
    ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
    ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
})
```

Default scopes are `openid email profile`. `EmailVerified` is mapped from
Google's `email_verified` userinfo claim (true only when Google attests).

### Microsoft (v0.4)

Register at https://entra.microsoft.com/ under App registrations, add the
redirect URI `https://yourapp.com/auth/providers/microsoft/callback`, then:

```go
import "github.com/glincker/theauth-go/provider/microsoft"

microsoft.New(microsoft.Config{
    ClientID:     os.Getenv("MS_CLIENT_ID"),
    ClientSecret: os.Getenv("MS_CLIENT_SECRET"),
    Tenant:       os.Getenv("MS_TENANT"), // optional; defaults to "common"
})
```

`Tenant` is substituted into the authorize and token URLs. Valid values:

- `common` (default): any work, school, or personal Microsoft account
- `organizations`: work / school only
- `consumers`: personal only
- a tenant GUID or verified domain (e.g. `contoso.onmicrosoft.com`) for
  single-tenant apps

Microsoft's OIDC userinfo endpoint does not return an `email_verified`
claim, so `ProviderUser.EmailVerified` is always `false`. The find or
create flow treats this as soft verification: the address is surfaced for
matching, but the user record is created with `EmailVerifiedAt=nil`, and
your app can require an extra verification step before granting elevated
permissions.

### Discord (v0.4)

Register at https://discord.com/developers/applications, add the redirect
URI `https://yourapp.com/auth/providers/discord/callback`, then:

```go
import "github.com/glincker/theauth-go/provider/discord"

discord.New(discord.Config{
    ClientID:     os.Getenv("DISCORD_CLIENT_ID"),
    ClientSecret: os.Getenv("DISCORD_CLIENT_SECRET"),
})
```

Default scopes are `identify email`. The avatar URL is synthesized from
the user's avatar hash (`https://cdn.discordapp.com/avatars/{id}/{hash}.png`);
users without a custom avatar receive an empty `AvatarURL` so consumers
can render their own placeholder.

### Routes (any provider)

`a.Mount(r)` adds two routes per registered provider, keyed by
`Provider.Name()`:

| Method + path                                          | Notes                                                  |
| ------------------------------------------------------ | ------------------------------------------------------ |
| `GET /auth/providers/{name}/start`                     | 302 to the provider's authorize URL, sets state cookie |
| `GET /auth/providers/{name}/callback`                  | exchanges code, sets session cookie                    |

`{name}` is `github`, `google`, `microsoft`, or `discord` depending on
which providers you wired up.

Built-in safeguards:

- **PKCE S256** on every flow (no plaintext code_verifier on the wire)
- **State cookie + query parameter** must match before code exchange (CSRF)
- **State entries expire after 10 minutes** and are GC-swept every minute
- **Tokens encrypted at rest** with AES-256-GCM via `Config.EncryptionKey`
- **Primary verified email only** counts as verified on `User.EmailVerifiedAt`
- **Same rate limit** as credential endpoints (5/min per IP by default)

Find-or-create resolves a returning OAuth user in this order: (1) existing
`oauth_accounts` row by provider + provider user id, (2) match by verified
email on the existing users table, (3) create a brand new user. The
upstream access/refresh tokens are persisted (encrypted) so v0.4 refresh
rotation can light up without a schema change.

---

## WebAuthn / passkeys (v0.5)

WebAuthn ships behind `Config.WebAuthn`. Routes mount only when the block
is non-nil, so existing apps see no behavior change after upgrading.

```go
import "github.com/glincker/theauth-go"

a, _ := theauth.New(theauth.Config{
    Storage:       postgres.New(pool),
    BaseURL:       "https://yourapp.com",
    EncryptionKey: key, // 32 bytes; reuses the same key OAuth tokens ride on
    WebAuthn: &theauth.WebAuthnConfig{
        RPID:          "yourapp.com",            // eTLD+1, no scheme, no port
        RPDisplayName: "Your App",                // shown in browser prompts
        RPOrigins:     []string{"https://yourapp.com"},
    },
})
```

Routes:

| Method + path | Auth | Purpose |
| --- | --- | --- |
| `POST /auth/webauthn/register/begin` | RequireAuth (full) | Returns `protocol.CredentialCreation`, sets challenge cookie |
| `POST /auth/webauthn/register/finish` | RequireAuth (full) | Validates attestation, stores credential row |
| `POST /auth/webauthn/login/begin` | none | Returns discoverable `protocol.CredentialAssertion` |
| `POST /auth/webauthn/login/finish` | none | Validates assertion, issues full session cookie |
| `GET /auth/webauthn/credentials` | RequireAuth (full) | Lists the caller's registered credentials |
| `DELETE /auth/webauthn/credentials/{id}` | RequireAuth (full) | Removes one credential |

Built-in safeguards:

- **PKCE-equivalent challenge binding** via an HttpOnly cookie scoped to `/auth/webauthn`
- **Single-use challenge entries** (LoadAndDelete before validate)
- **5 minute TTL** on every challenge, swept every 60s
- **Sign-count replay protection** via an atomic `UPDATE ... WHERE sign_count < $new` plus a lookup follow-up to disambiguate replay from missing row
- **Discoverable-only login** so the begin endpoint reveals nothing about user existence
- **Single-factor-strong** per NIST SP 800-63B rev 4: a passkey login is a strong factor by itself, so the flow does NOT step up to TOTP

Passkey ceremonies on the client side use the standard `navigator.credentials.create`
and `navigator.credentials.get` APIs; the server returns the unmodified
`protocol.CredentialCreation` / `protocol.CredentialAssertion` JSON for the
browser to consume directly. See `examples/webauthn-passkey/` for a small
single-page demo with a working register and login button pair.

---

## TOTP 2FA + recovery codes (v0.5)

TOTP ships behind `Config.TOTP`. Like WebAuthn, the routes only mount
when the block is non-nil.

```go
import "github.com/glincker/theauth-go"

a, _ := theauth.New(theauth.Config{
    Storage:       postgres.New(pool),
    BaseURL:       "https://yourapp.com",
    EncryptionKey: key, // 32 bytes; required, used to encrypt totp_secrets.secret_enc
    TOTP: &theauth.TOTPConfig{
        Issuer: "Your App", // shown in Google Authenticator, Authy, 1Password
        // RecoveryCodeCount defaults to 10
    },
})
```

Routes:

| Method + path | Auth | Purpose |
| --- | --- | --- |
| `POST /auth/totp/enroll/begin` | RequireAuth (full) | Generates secret, returns `{secret, otpAuthUrl, enrollmentId}` |
| `POST /auth/totp/enroll/finish` | RequireAuth (full) | Body `{enrollmentId, code}`. Confirms secret, returns 10 recovery codes (once) |
| `POST /auth/totp/verify` | RequirePendingOrFull | Body `{code}`. Promotes pending session to full |
| `POST /auth/totp/recovery` | RequirePendingOrFull | Body `{code}`. Consumes one recovery code, promotes session |
| `DELETE /auth/totp` | RequireAuth (full) | Drops the secret + all recovery codes |

When `Config.TOTP != nil` and a user has confirmed TOTP, the
`POST /auth/email-password/signin` response shape becomes
`{"step":"totp_required"}` and the session cookie carries a
`pending_2fa` AuthLevel that only the two verify routes accept.

Session state machine:

```
anon
  |
  | POST /auth/email-password/signin (no TOTP enrolled)
  | GET  /auth/magic-link/verify
  | GET  /auth/providers/{name}/callback
  | POST /auth/webauthn/login/finish
  v
full  (auth_level = 'full', all RequireAuth routes)
  |
  | DELETE /auth/sessions/current
  v
anon

anon
  |
  | POST /auth/email-password/signin (TOTP confirmed for user)
  v
pending_2fa  (auth_level = 'pending_2fa', 10 min TTL)
  |
  | POST /auth/totp/verify   (valid code)
  | POST /auth/totp/recovery (valid unused recovery code)
  v
full
```

Built-in safeguards:

- **AES-GCM at rest** for `totp_secrets.secret_enc` (mandatory; `New` errors if `EncryptionKey` is missing)
- **Per-code salted SHA-256** for recovery codes (40 bit `crypto/rand` entropy makes Argon2id wasted latency; see `crypto/recoverycode.go`)
- **Five-strike pending session revocation**: five consecutive wrong codes revoke the pending session and force a fresh password verify
- **WebAuthn login bypasses TOTP**: NIST SP 800-63B rev 4 treats passkey as a single strong factor
- **OAuth callbacks bypass TOTP**: the IdP already enforced its own factors

See `examples/totp-stepup/` for a single-page demo of the full flow.

---

## Comparison

How `theauth-go` stacks up against the libraries and services you would actually consider in 2026:

| Feature                       | theauth-go    | better-auth   | Auth0 SDK    | Stytch       | Ory Kratos    |
| ----------------------------- | ------------- | ------------- | ------------ | ------------ | ------------- |
| Language                      | Go            | TypeScript    | Multiple     | Multiple     | Go            |
| Magic links                   | Shipping      | Shipping      | Shipping     | Shipping     | Shipping      |
| Email / password              | Shipping      | Shipping      | Shipping     | Shipping     | Shipping      |
| OAuth providers               | 4             | 17            | 30+          | 20+          | 10+           |
| Passkeys / WebAuthn           | Shipping      | Shipping      | Shipping     | Shipping     | Shipping      |
| TOTP 2FA + recovery codes     | Shipping      | Shipping      | Shipping     | Shipping     | Shipping      |
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
                │   ├── password service       │  argon2id, rate-limited (v0.2)
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
- **`email.SMTP`** — minimal SMTP sender (host, port, from). Lands in v0.3
- **Custom** — implement `email.Sender` to wire Resend, Postmark, SES, SendGrid, etc.

---

## Roadmap

- **v0.1** Magic links, sessions, chi middleware, Postgres + in-memory storage (shipped)
- **v0.2** Email + password (signup, signin, forgot, reset), argon2id, per-IP + per-email rate limiting, structured `TheAuthError` type (shipped)
- **v0.3** GitHub OAuth (Provider interface + PKCE S256), AES-GCM token-at-rest encryption (shipped)
- **v0.4** Google + Microsoft + Discord OAuth (shipped)
- **v0.5** WebAuthn / passkeys, TOTP 2FA + recovery codes, session step-up state machine (shipped)
- **v0.6** Refresh-token rotation, JWKS-backed `id_token` verification, SMTP sender
- **v1.0** All 17 OAuth providers + SAML 2.0
- **v2.0** MCP OAuth 2.1 server, agent identity, delegation chains, budget policies

Track the work in [GitHub Issues](https://github.com/glincker/theauth-go/issues) and [Releases](https://github.com/glincker/theauth-go/releases).

---

## FAQ

### Is `theauth-go` production-ready?

v0.1 ships sessions and magic links and is covered by unit + integration tests against Postgres. v0.2 adds email + password with argon2id hashing, rate limiting, and anti-enumeration safeguards. It is appropriate for greenfield projects and side projects today. OAuth lands in v0.3. If you need OAuth, passkeys, or 2FA right now, check the roadmap and pick the right version — or use one of the alternatives above and migrate later.

### Why not just use Auth0 or Clerk?

Both are excellent if you are happy paying per monthly active user and letting a third party hold your identity data. `theauth-go` exists for teams that want self-hosted, MIT-licensed, no-per-MAU-cost auth they fully control — including the code path that runs at login.

### Why not Ory Kratos?

Kratos is a separate service you run alongside your app. `theauth-go` is a library you import — same process, same DB, same deploy. Fewer moving parts, less ops burden, but you give up Kratos's UI flows and multi-language SDK. Pick Kratos if you need a polyglot stack; pick `theauth-go` if your backend is Go and you want library-grade simplicity.

### Why not better-auth?

`better-auth` is the TypeScript reference for this design. If your stack is Node/Next.js, use it (or use the sibling [`glincker/theauth`](https://github.com/glincker/theauth) TS implementation). `theauth-go` exists because the Go ecosystem deserves the same ergonomics natively, not via a Node sidecar.

### Why a new Go auth library?

No Go library today combines agent identity + MCP OAuth 2.1 + traditional human auth in a single package. `theauth-go` is built for the moment human and agent auth converge — sessions, magic links, and email + password today, OAuth and passkeys in 2026, MCP OAuth 2.1 server + delegation in v2.0.

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
