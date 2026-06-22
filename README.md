<!-- keywords: oauth2 oauth-server oidc mcp mcp-authorization go golang authorization-server pkce jwt saml scim webauthn totp rbac ed25519 postgres agent-identity delegation -->

# theauth-go

[![Go Reference](https://pkg.go.dev/badge/github.com/glincker/theauth-go.svg)](https://pkg.go.dev/github.com/glincker/theauth-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/glincker/theauth-go)](https://goreportcard.com/report/github.com/glincker/theauth-go)
[![CI](https://github.com/glincker/theauth-go/actions/workflows/ci.yml/badge.svg)](https://github.com/glincker/theauth-go/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/glincker/theauth-go)](https://github.com/glincker/theauth-go/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A Go auth library that covers magic links, email and password, OAuth providers, passkeys, TOTP, SAML, SCIM, multi-tenancy, RBAC, an OAuth 2.1 authorization server, agent identities, and revocable delegation chains, all behind a single `go get`. v2.0.0 is the production release.

It is the first Go auth library where oauth 2.1 mcp authorization, agent identities, and revocable delegation chains ship in a single import. It drops into a `chi` or `net/http` server in under twenty lines and stores sessions in postgres or memory.

---

## Documentation

Full documentation is available at **https://glincker.github.io/theauth-go/**

The site covers getting started, concepts, guides, configuration reference, error catalog, metrics and spans, audit events, migration guides, and security.

---

## Contents

- [Features](#features)
- [Quick start](#quick-start)
- [MCP resource server quickstart](#mcp-resource-server-quickstart)
- [Documentation](#documentation)
- [Examples](#examples)
- [Architecture](#architecture)
- [Security](#security)
- [Versioning and stability](#versioning-and-stability)
- [Verifying releases](#verifying-releases)
- [Contributing](#contributing)
- [License](#license)
- [Acknowledgements](#acknowledgements)

---

## Features

### Identity and session management

- Opaque session tokens with `HttpOnly`, `Secure`, `SameSite=Lax` cookies; only a SHA-256 hash is persisted
- Magic-link sign-in
- Email and password with Argon2id (OWASP 2026 defaults), minimum 12-char enforcement, anti-enumeration safeguards
- Per-IP and per-email rate limiting on every credential endpoint
- WebAuthn / passkeys: discoverable login, sign-count replay protection, single-factor-strong per NIST SP 800-63B
- TOTP second factor with 10 single-use recovery codes and a `pending_2fa` session step-up state machine

### OAuth 2.1 authorization server

- `/.well-known/oauth-authorization-server` (RFC 8414), `/oauth/authorize`, `/oauth/token`, `/oauth/revoke`, `/oauth/introspect`, `/oauth/jwks`
- RFC 9068 JWT access tokens signed with Ed25519 (30-day JWKS rotation)
- RFC 8707 mandatory audience binding
- PKCE S256 mandatory
- RFC 9700 refresh-token rotation with family revocation on replay
- RFC 7591 dynamic client registration with bearer-gated initial access tokens

### MCP authorization

- First-class agent identities (user-owned or org-owned) with audited lifecycle (active, suspended, revoked)
- `client_credentials` grant for agent self-tokens
- RFC 8693 token-exchange grant: scope narrowing, duration tightening, actor chain capped at 3
- RFC 9728 protected-resource metadata at `/.well-known/oauth-protected-resource`
- `mcpresource` SDK: a zero-dependency Go module for MCP resource servers. Wire one middleware for JWT validation, audience enforcement, actor-chain walking, and revocation propagation

### Enterprise

- SAML 2.0 Service Provider (per-organization IdP binding, signed assertions only, find-or-create)
- SCIM 2.0 provisioning: Users and Groups CRUD, RFC 7644 PATCH, sha256 bearer tokens, per-org isolation
- Organizations multi-tenancy with `active_organization_id` session scope
- RBAC with a closed permission catalog, seeded roles, and `RequirePermission` middleware

### Hardening and observability

- Append-only async audit log with default redactor and keyset pagination
- Admin HTTP API at `/admin/v1` with RFC 7807 problem+json errors
- Fuzz tests, race-clean test suite, benchmark baselines in `internal/bench/BASELINES.md`
- Pluggable `Storage` interface: in-memory (zero deps) or postgres (`pgx/v5` + `sqlc`)

---

## Quick start

```bash
go get github.com/glincker/theauth-go
```

Requires **Go 1.25+**.

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

Run it:

```bash
go run main.go
# POST http://localhost:8080/auth/magic-link  {"email":"you@example.com"}
```

For postgres storage:

```go
pool, _ := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
a, _ := theauth.New(theauth.Config{
    Storage: postgres.New(pool),
    BaseURL: "https://myapp.com",
})
```

---

## MCP resource server quickstart

```bash
go get github.com/glincker/theauth-go/mcpresource
```

The `mcpresource` module has no third-party dependencies. Importing it does not pull in theauth core or any storage adapter.

```go
package main

import (
    "net/http"

    "github.com/glincker/theauth-go/mcpresource"
    "github.com/go-chi/chi/v5"
)

func main() {
    v := mcpresource.New(
        "https://mcp.example.com",
        mcpresource.WithJWKS("https://as.example.com/oauth/jwks"),
        mcpresource.WithIntrospection(
            "https://as.example.com/oauth/introspect",
            "mcp-client-id",
            "mcp-client-secret",
        ),
    )

    r := chi.NewRouter()
    r.Use(v.Middleware)
    r.Get("/tools/run", func(w http.ResponseWriter, r *http.Request) {
        p, _ := v.Principal(r.Context())
        _ = p // p.Subject (user), p.Actor (final agent), p.ActorChain
    })

    _ = http.ListenAndServe(":8090", r)
}
```

The middleware validates the bearer JWT against a cached JWKS, enforces the audience claim, checks expiry with a 60-second skew tolerance, walks the RFC 8693 `act` chain via AS introspection, and on failure emits 401 with `WWW-Authenticate: Bearer error="invalid_token", resource_metadata="..."` per RFC 6750 and RFC 9728.

Full runnable example: [`examples/mcp-server/`](./examples/mcp-server).

---

## Documentation

| Document | Description |
| --- | --- |
| [AGENTS.md](AGENTS.md) | Concise reference for AI coding assistants: patterns, anti-patterns, file map |
| [STABILITY.md](STABILITY.md) | Public API surface, SemVer rules, Storage interface special rules |
| [CHANGELOG.md](CHANGELOG.md) | Per-release notable changes following Keep a Changelog |
| [SECURITY.md](SECURITY.md) | Vulnerability disclosure policy and contact |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Dev setup, test commands, commit convention, PR process |
| [docs/positioning.md](docs/positioning.md) | Why MCP OAuth 2.1 matters and what theauth-go ships for it |
| [internal/bench/BASELINES.md](internal/bench/BASELINES.md) | v0.6 benchmark baselines for five hot paths |

### HTTP surface reference

**Auth flows** (mounted by `a.Mount(r)`):

| Endpoint | Purpose |
| --- | --- |
| `POST /auth/magic-link` | Request a sign-in link |
| `GET /auth/magic-link/verify` | Consume the link token, issue session |
| `POST /auth/email-password/signup` | Register, sets session cookie |
| `POST /auth/email-password/signin` | Sign in, sets session cookie |
| `POST /auth/email-password/forgot` | Request a password reset (silently 200 for unknown emails) |
| `POST /auth/email-password/reset` | Consume reset token, revoke all sessions |
| `GET /auth/me` | Current user (requires auth) |
| `DELETE /auth/sessions/current` | Sign out |

**OAuth providers** (`GET /auth/providers/{name}/start` and `/callback`): github, google, microsoft, discord, facebook, slack, gitlab, bitbucket, twitch, linkedin, x, apple.

| Provider | Package | Protocol | Notes |
| --- | --- | --- | --- |
| GitHub | `provider/github` | OAuth 2.0 + PKCE | [docs](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps) |
| Google | `provider/google` | OIDC | [docs](https://developers.google.com/identity/protocols/oauth2) |
| Microsoft | `provider/microsoft` | OIDC (Entra ID) | [docs](https://learn.microsoft.com/en-us/entra/identity-platform/) |
| Discord | `provider/discord` | OAuth 2.0 + PKCE | [docs](https://discord.com/developers/docs/topics/oauth2) |
| Facebook | `provider/facebook` | OAuth 2.0 + PKCE | [docs](https://developers.facebook.com/docs/facebook-login/) |
| Slack | `provider/slack` | OIDC (Sign in with Slack) | [docs](https://api.slack.com/authentication/sign-in-with-slack) |
| GitLab | `provider/gitlab` | OIDC; configurable BaseURL for self-hosted | [docs](https://docs.gitlab.com/ee/integration/openid_connect_provider.html) |
| Bitbucket | `provider/bitbucket` | OAuth 2.0 + PKCE | [docs](https://support.atlassian.com/bitbucket-cloud/docs/use-oauth-on-bitbucket-cloud/) |
| Twitch | `provider/twitch` | OIDC | [docs](https://dev.twitch.tv/docs/authentication/getting-tokens-oidc/) |
| LinkedIn | `provider/linkedin` | OIDC (/v2/userinfo) | [docs](https://learn.microsoft.com/en-us/linkedin/consumer/integrations/self-serve/sign-in-with-linkedin-v2) |
| X (Twitter) | `provider/x` | OAuth 2.0; PKCE mandatory | [docs](https://developer.x.com/en/docs/authentication/oauth-2-0/authorization-code) |
| Apple | `provider/apple` | OIDC; JWT client secret (ES256) | [docs](https://developer.apple.com/documentation/sign_in_with_apple) |

**WebAuthn**: `/auth/webauthn/register/{begin,finish}`, `/auth/webauthn/login/{begin,finish}`, `/auth/webauthn/credentials`.

**TOTP**: `/auth/totp/enroll/{begin,finish}`, `/auth/totp/verify`, `/auth/totp/recovery`, `DELETE /auth/totp`.

**OAuth 2.1 AS** (enabled via `Config.AuthorizationServer`): `/.well-known/oauth-authorization-server`, `/oauth/{authorize,token,revoke,introspect,register,jwks}`, `/.well-known/oauth-protected-resource`.

**Admin API** (enabled via `Config.Admin`, requires RBAC): `/admin/v1/users`, `/admin/v1/sessions`, `/admin/v1/audit`, `/admin/v1/organizations/{orgID}/agents`, `/admin/v1/organizations/{orgID}/delegations`.

**Account UX** (enabled via `Config.AccountUX`): `/account/agents`, `/account/delegations`.

---

## Examples

| Example | What it shows |
| --- | --- |
| [`examples/chi-app/`](./examples/chi-app) | Magic links and email/password with chi |
| [`examples/gin-app/`](./examples/gin-app) | Drop-in with Gin |
| [`examples/echo-app/`](./examples/echo-app) | Drop-in with Echo |
| [`examples/stdlib-app/`](./examples/stdlib-app) | Pure `net/http`, no framework |
| [`examples/oauth-multi-provider/`](./examples/oauth-multi-provider) | GitHub + Google + Microsoft + Discord in one app |
| [`examples/oauth-facebook/`](./examples/oauth-facebook) | Sign in with Facebook (Meta) |
| [`examples/oauth-slack/`](./examples/oauth-slack) | Sign in with Slack (OpenID Connect) |
| [`examples/oauth-gitlab/`](./examples/oauth-gitlab) | Sign in with GitLab (self-hosted or gitlab.com) |
| [`examples/oauth-bitbucket/`](./examples/oauth-bitbucket) | Sign in with Bitbucket Cloud |
| [`examples/oauth-twitch/`](./examples/oauth-twitch) | Sign in with Twitch (OIDC) |
| [`examples/oauth-linkedin/`](./examples/oauth-linkedin) | Sign in with LinkedIn (OIDC /v2/userinfo) |
| [`examples/oauth-x/`](./examples/oauth-x) | Sign in with X/Twitter (PKCE mandatory) |
| [`examples/oauth-apple/`](./examples/oauth-apple) | Sign in with Apple (JWT client secret) |
| [`examples/webauthn-passkey/`](./examples/webauthn-passkey) | Passkey register and discoverable login |
| [`examples/totp-stepup/`](./examples/totp-stepup) | Password + TOTP step-up flow |
| [`examples/mcp-server/`](./examples/mcp-server) | MCP resource server using `mcpresource` middleware |

Each example has a `README`, single-file `main.go`, `go.mod`, `docker-compose.yml`, `.env.example`, and `Makefile`.

---

## Architecture

```
                ┌──────────────────────────────┐
   HTTP req ->  │  chi / net/http router       │
                │   ├── a.Mount(r)             │  /auth/* handlers
                │   └── a.RequireAuth()        │  middleware
                └──────────────┬───────────────┘
                               │
                ┌──────────────▼───────────────┐
                │  theauth core                │
                │   ├── magic-link service     │
                │   ├── session service        │  opaque tokens, SHA-256 in DB
                │   ├── password service       │  argon2id, rate-limited
                │   ├── oauth / MCP / agents   │  v0.3 to v2.0
                │   └── audit / RBAC           │  v1.0+
                └──────────────┬───────────────┘
                               │
                ┌──────────────▼───────────────┐
                │  Storage interface           │  pluggable
                │   ├── storage/memory         │  tests, demos
                │   └── storage/postgres       │  pgx + sqlc
                └──────────────────────────────┘
```

Sessions are opaque tokens. The raw token lives only in the user's cookie; only a SHA-256 hash is persisted. Revocation is a single `UPDATE`. The `Storage` interface is the only surface a custom backend needs to implement.

The `mcpresource` module is a separately versioned zero-dependency module. A consumer importing it does not transitively pull theauth core or any storage adapter.

---

## Writing a custom storage backend

Implement [`theauth.Storage`](storage.go) (core auth methods) and optionally
[`theauth.OAuthServerStorage`](storage_v20.go) (OAuth 2.1 AS methods). Pass
the instance to `theauth.New(cfg)` via `Config.Storage`.

To prove your backend is conformant, import [`storagetest`](storagetest/doc.go)
in a test file and call `storagetest.Run`:

```go
import (
    "testing"

    "github.com/glincker/theauth-go/storagetest"
)

func TestMyBackendContract(t *testing.T) {
    store := mybackend.New(/* your config */)
    storagetest.Run(t, store)
}
```

`storagetest.Run` exercises 14 domain sub-tests covering users, sessions,
magic links, passwords, WebAuthn, TOTP, audit events, RBAC roles, OAuth
clients, authorization codes, refresh tokens, JWKS keys, agents, and
delegation grants. Passing all sub-tests means your backend satisfies the
same semantics as the built-in `storage/memory` and `storage/postgres`
adapters.

Backends that only implement `theauth.Storage` (not `OAuthServerStorage`)
will see the OAuth AS sub-tests automatically skipped with `t.Skip`.

The `storagetest` package has no external dependencies beyond the standard
library and `theauth` itself.

---

## Security

See [SECURITY.md](SECURITY.md) for the vulnerability disclosure policy. Report security issues to `security@glincker.com`.

Recent security work (2026-06-20 audit):

- POST `/oauth/register` bearer gate now validates tokens with `crypto/subtle.ConstantTimeCompare` against pre-hashed sha256 digests
- POST `/oauth/register` is rate-limited per source IP (1 req/min for anonymous mode, 5 req/min for bearer-gated mode)
- `X-Forwarded-For` is no longer trusted by default. Set `Config.TrustedProxies` to opt in
- Cross-org delegation admin grants now verify `body.userId` is a member of the caller's organization
- Password signin pays full Argon2id cost on unknown-email and empty-password branches (timing side-channel closed)

---

## Versioning and stability

The project follows [Semantic Versioning](https://semver.org/) from v1.0 forward. v2.0.0 is the current production release. The v1.0 public API surface is frozen. Every v2.0 feature (OAuth 2.1 AS, agent identities, delegation, `mcpresource`) is opt-in via additional `Config` fields; callers who upgrade from v1.0 without setting those fields see no behavior change.

See [STABILITY.md](STABILITY.md) for the complete list of stable symbols, the Storage interface special rule, and the migration append-only guarantee.

---

## Verifying releases

Every release is signed with [Sigstore](https://www.sigstore.dev/) keyless
cosign and includes a CycloneDX SBOM. The full release process is documented
in [docs/RELEASING.md](docs/RELEASING.md).

### Install this library

```bash
go get github.com/glincker/theauth-go@vX.Y.Z
```

(`go install` is for CLI tools; this is a library, so `go get` is correct.)

### Verify the SBOM signature

Download the `.sbom.json`, `.sbom.json.sig`, and `.sbom.json.cert` files from
the [GitHub release](https://github.com/glincker/theauth-go/releases), then:

```bash
cosign verify-blob \
  --certificate-identity "https://github.com/glincker/theauth-go/.github/workflows/release.yml@refs/tags/vX.Y.Z" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --signature theauth-go-vX.Y.Z.tar.gz.sbom.json.sig \
  --certificate theauth-go-vX.Y.Z.tar.gz.sbom.json.cert \
  theauth-go-vX.Y.Z.tar.gz.sbom.json
```

A `Verified OK` response confirms the SBOM was produced by the official release
workflow from the tagged commit with no tampering.

### Read the SBOM

The SBOM lists every Go module dependency, its version, and its license. Feed
it to any CycloneDX-compatible scanner (e.g. `grype`, `trivy`, Dependency-Track)
to run license compliance or vulnerability checks against the exact dependency
set shipped in a given release.

### Verify SLSA provenance

The release workflow also generates a SLSA provenance attestation stored in
GitHub's artifact store. Verify it with the `gh` CLI:

```bash
gh attestation verify theauth-go-vX.Y.Z.tar.gz --repo glincker/theauth-go
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for dev setup, test commands, lint, commit convention, and the PR process.

- Bug reports and feature requests: [GitHub Issues](https://github.com/glincker/theauth-go/issues)
- Design discussions and RFC threads: [GitHub Discussions](https://github.com/glincker/theauth-go/discussions)
- Pull requests: open an issue first for anything beyond a typo or one-file fix

---

## License

MIT. See [LICENSE](./LICENSE).

---

## Acknowledgements

Built on and interoperating with:

- [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749) OAuth 2.0 Authorization Framework
- [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750) Bearer Token Usage
- [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517) JSON Web Key
- [RFC 7591](https://www.rfc-editor.org/rfc/rfc7591) Dynamic Client Registration
- [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636) PKCE
- [RFC 7662](https://www.rfc-editor.org/rfc/rfc7662) Token Introspection
- [RFC 7807](https://www.rfc-editor.org/rfc/rfc7807) Problem Details for HTTP APIs
- [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414) Authorization Server Metadata
- [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693) OAuth 2.0 Token Exchange
- [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707) Resource Indicators
- [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068) JWT Profile for OAuth 2.0 Access Tokens
- [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700) OAuth 2.0 Best Current Practices
- [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728) OAuth 2.0 Protected Resource Metadata
- OAuth 2.1 draft and MCP Authorization specification (2025-11-25)
- [crewjam/saml](https://github.com/crewjam/saml) v0.5.1 for SAML 2.0 SP ceremonies
- [go-webauthn/webauthn](https://github.com/go-webauthn/webauthn) for WebAuthn / passkey ceremonies
- TypeScript sibling: [glincker/theauth](https://github.com/glincker/theauth)
