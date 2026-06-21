# theauth-go for AI agents

This file helps AI coding assistants (Claude Code, Cursor, GitHub Copilot, Windsurf, Cline, Continue) understand how to use this library correctly. If you are a human reader, the [README](./README.md) is the better starting point.

## What this is

`theauth-go` is a Go library for session-based authentication. It ships:

- **v0.1 (shipped)**: magic-link sign-in, opaque session tokens, `chi` + `net/http` middleware, Postgres + in-memory storage
- **v0.2 (shipped)**: email + password (signup, signin, forgot, reset), argon2id hashing, per-IP + per-email rate limiting, structured `TheAuthError` type
- **v0.3 (shipped)**: GitHub OAuth, extensible `Provider` interface, PKCE S256, AES-GCM token-at-rest encryption
- **v0.4 (shipped)**: Google, Microsoft, Discord OAuth providers (same `Provider` interface, no core changes)
- **v0.5 (shipped)**: WebAuthn / passkeys (discoverable login + replay-protected registration), TOTP 2FA + 10 single-use recovery codes, session step-up state machine (`pending_2fa` -> `full`)
- **v0.6 (shipped)**: hardening release. Fuzz tests, race tests, benchmark baselines, four new examples (gin, echo, stdlib, oauth-multi-provider), package documentation, `STABILITY.md`, `CHANGELOG.md`. No new features.
- **v0.7 (shipped)**: SAML 2.0 Service Provider (per-connection IdP binding, signed assertions only, find-or-create), SCIM 2.0 provisioning (Users + Groups + Discovery, eq-only filter, RFC 7644 PATCH, sha256 bearer tokens), organizations multi-tenancy (`organizations`, `organization_members`, `sessions.active_organization_id`). Migrations 0006 / 0007 / 0008. Audit hook stub (v1.0 wires the real async writer).
- **v1.0 (shipped)**: organization-scoped RBAC with twelve seeded permissions and three default roles, append-only async audit log with default redactor and keyset pagination, admin API at `/admin/v1` with RFC 7807 problem+json errors. Migrations 0009 (rbac) and 0010 (audit). Public API frozen per [STABILITY.md](STABILITY.md).
- **v2.0 phase 1 + 2 (shipped, pre-release `v2.0.0-alpha.1`)**: OAuth 2.1 authorization server (`/.well-known/oauth-authorization-server`, `/oauth/authorize`, `/oauth/token`, `/oauth/revoke`, `/oauth/introspect`), RFC 7591 dynamic client registration (`/oauth/register`), JWKS (`/oauth/jwks`) with 30-day Ed25519 rotation, RFC 9068 signed JWT access tokens, RFC 8707 mandatory audience binding, PKCE S256 mandatory. Migrations 0011 (oauth clients + codes + refresh tokens) and 0014 (jwks keys). v1.0 public surface unchanged: all v2.0 features are opt-in via `Config.AuthorizationServer`.
- **v2.0 phase 3 + 4 (shipped, pre-release `v2.0.0-alpha.2`)**: agent identity primitives (Agent, AgentCredential, owner = user or organization), the OAuth 2.0 client_credentials grant for agent self-tokens, delegation grants (one row per (user, agent, resource) triple), and the RFC 8693 token-exchange grant with strict scope narrowing, strict duration tightening, and a hard chain depth cap of 3. Introspection walks the actor chain on every call so revocations propagate within `IntrospectionCacheTTL`. Migrations 0012 (agents + agent_credentials) and 0013 (delegation_grants + audit_events.actor_agent_id). All wiring opt-in via `Config.AgentIdentity`.
- **v2.0 phase 5 + 6 (shipped, `v2.0.0`)**: `mcpresource` SDK (separate zero-dependency Go module: `github.com/glincker/theauth-go/mcpresource`), RFC 9728 OAuth 2.0 Protected Resource Metadata (`/.well-known/oauth-protected-resource[/{path}]`), organization-scoped admin UX (`/admin/v1/organizations/{orgID}/agents` and `/delegations`, gated by the new seeded permissions `agents:admin` and `delegations:admin`), and end-user self-service UX (`/account/agents` and `/account/delegations`, gated by session cookie). v2.0 is now feature complete. v1.0 stability surface is unchanged: every v2.0 feature is opt-in via additional `Config` fields.

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
- **Enable Google / Microsoft / Discord OAuth (v0.4)**: same pattern as GitHub. Import the relevant sub-package (`provider/google`, `provider/microsoft`, `provider/discord`), construct with `<pkg>.New(<pkg>.Config{ClientID, ClientSecret})`, and add to `Config.Providers`. Microsoft also accepts `Tenant` (defaults to `"common"`; pass a tenant GUID or verified domain for single tenant apps). Routes mount at `/auth/providers/{name}/start` and `/callback` per provider
- **Enable WebAuthn passkeys (v0.5)**: set `Config.WebAuthn = &theauth.WebAuthnConfig{RPID: "yourapp.com", RPDisplayName: "Your App", RPOrigins: []string{"https://yourapp.com"}}`. Routes mount at `/auth/webauthn/register/{begin,finish}`, `/auth/webauthn/login/{begin,finish}`, and `/auth/webauthn/credentials`. Passkey login bypasses TOTP step-up by design (single-factor-strong per NIST SP 800-63B rev 4)
- **Enable TOTP 2FA (v0.5)**: set `Config.TOTP = &theauth.TOTPConfig{Issuer: "Your App"}` plus a 32 byte `Config.EncryptionKey`. Routes mount at `/auth/totp/enroll/{begin,finish}`, `/auth/totp/verify`, `/auth/totp/recovery`, and `DELETE /auth/totp`. Password signin returns `{"step":"totp_required"}` when the user has a confirmed secret; the cookie carries a `pending_2fa` session that only the verify routes accept
- **Enable agents and delegation (v2.0 phase 3 + 4)**: set `Config.AgentIdentity = &theauth.AgentConfig{}` alongside `Config.AuthorizationServer`. The `/oauth/token` endpoint then accepts `grant_type=client_credentials` (agent self-tokens, `sub=agent:<id>`) and `grant_type=urn:ietf:params:oauth:grant-type:token-exchange` (RFC 8693, with the actor chain capped at 3 and strict scope and duration narrowing on every mint). Provision agents with `a.CreateAgent(ctx, theauth.CreateAgentInput{...})`; record user approvals with `a.GrantDelegation(ctx, theauth.GrantDelegationInput{...})`. Revoking a delegation flips every derived token's introspection result to `active=false` inside `IntrospectionCacheTTL` (default 60s)
- **Trust a reverse proxy for X-Forwarded-For (security audit H4, 2026-06-20)**: set `Config.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}` (or your LB's actual CIDR). Without this, XFF is ignored and the rate limiter keys off `r.RemoteAddr` only, which is the safe default for a direct public-internet bind. Multiple prefixes are supported; the allowlist applies to every middleware that consults the client IP
- **Issue an initial access token for DCR (security audit H1, 2026-06-20)**: set `AuthorizationServerConfig.RegistrationTokens = []string{"<your-secret>"}` and hand the secret to your registration tooling out of band. The handler validates the supplied bearer with `crypto/subtle.ConstantTimeCompare` against a pre-hashed snapshot built at `New` time; arbitrary bearers are rejected with 401 access_denied. When `RegistrationTokens` is empty AND `AllowAnonymousRegistration` is false (the default), every DCR request is denied. POST `/oauth/register` is rate limited (1/min/IP for anonymous mode, 5/min/IP for bearer-gated mode; configurable via `AuthorizationServerConfig.RegistrationRateLimitPerMinute`)

## What NOT to do

- **Do not hash tokens client-side** — pass the raw token from the cookie to the lib; it handles hashing
- **Do not use `email.Noop` in production** — it logs to stdout and never sends mail. Wire `email.SMTP` (v0.2+) or a custom `email.Sender`
- **Do not bypass `RequireAuth()` to check sessions manually** unless you are inside the library itself; the middleware enforces token shape, expiry, and revocation in one place
- **Do not invent OAuth APIs beyond the four shipped providers**: GitHub, Google, Microsoft, and Discord ship today (v0.3 + v0.4) via `provider/<name>`. WebAuthn passkeys and TOTP 2FA ship in v0.5. Refresh-token rotation and the remaining 13 OAuth providers (Apple, Facebook, Twitter / X, LinkedIn, GitLab, Bitbucket, etc.) are NOT shipped yet. Check the [roadmap](./README.md#roadmap) before generating
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
- `provider/github/`: GitHub `Provider` implementation (v0.3)
- `provider/google/`, `provider/microsoft/`, `provider/discord/`: v0.4 `Provider` implementations
- `provider/internal/oauthtest/`: shared httptest scaffolding used by the v0.4 provider tests; internal so external consumers cannot import it
- `service_webauthn.go` + `handlers_webauthn.go`: WebAuthn passkey registration + discoverable login (v0.5)
- `service_totp.go` + `handlers_totp.go`: TOTP enrollment, verify, recovery-code consumption, pending_2fa session state machine (v0.5)
- `crypto/aesgcm.go` + `crypto/pkce.go` + `crypto/recoverycode.go`: encryption, PKCE, recovery-code hashing primitives
- `internal/wavt/`: WebAuthn virtual-authenticator helper used by ceremony tests; internal
- `storage/` — `memory` and `postgres` adapters; the `Storage` interface lives at the package root
- `examples/chi-app/` — full runnable example
- `examples/webauthn-passkey/`: single-page passkey register + login demo (v0.5)
- `examples/totp-stepup/`: single-page password + TOTP step-up demo (v0.5)

## License and sibling project

MIT-licensed. TypeScript sibling: [`github.com/glincker/theauth`](https://github.com/glincker/theauth).
