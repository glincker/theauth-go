<!-- keywords: oauth2 oauth-server oidc mcp mcp-authorization go golang authorization-server pkce jwt saml scim webauthn totp rbac ed25519 postgres agent-identity delegation fapi dpop ciba par jar token-exchange -->

<div align="center">

```
████████╗██╗  ██╗███████╗ █████╗ ██╗   ██╗████████╗██╗  ██╗     ██████╗  ██████╗
╚══██╔══╝██║  ██║██╔════╝██╔══██╗██║   ██║╚══██╔══╝██║  ██║    ██╔════╝ ██╔═══██╗
   ██║   ███████║█████╗  ███████║██║   ██║   ██║   ███████║    ██║  ███╗██║   ██║
   ██║   ██╔══██║██╔══╝  ██╔══██║██║   ██║   ██║   ██╔══██║    ██║   ██║██║   ██║
   ██║   ██║  ██║███████╗██║  ██║╚██████╔╝   ██║   ██║  ██║    ╚██████╔╝╚██████╔╝
   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝     ╚═════╝  ╚═════╝
```

***OAuth 2.1 + MCP authorization for Go. Type-safe, dependency-light, FAPI-adjacent.***

[![Go Reference](https://pkg.go.dev/badge/github.com/glincker/theauth-go.svg)](https://pkg.go.dev/github.com/glincker/theauth-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/glincker/theauth-go)](https://goreportcard.com/report/github.com/glincker/theauth-go)
[![Release](https://img.shields.io/github/v/release/glincker/theauth-go?label=latest)](https://github.com/glincker/theauth-go/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/glincker/theauth-go/actions/workflows/ci.yml/badge.svg)](https://github.com/glincker/theauth-go/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/glincker/theauth-go/branch/main/graph/badge.svg)](https://codecov.io/gh/glincker/theauth-go)
[![Go](https://img.shields.io/badge/built%20with-Go-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![Postgres](https://img.shields.io/badge/storage-Postgres%20%7C%20MySQL%20%7C%20Memory-336791?logo=postgresql&logoColor=white)](storage/)
[![SLSA 3](https://slsa.dev/images/gh-badge-level3.svg)](https://github.com/glincker/theauth-go/releases)
[![SBOM](https://img.shields.io/badge/SBOM-Sigstore%20signed-blueviolet)](https://github.com/glincker/theauth-go/releases)

```bash
go get github.com/glincker/theauth-go
```

</div>

```go
a, _ := theauth.New(theauth.Config{
    Storage: memory.New(),
    BaseURL: "http://localhost:8080",
})
r := chi.NewRouter()
a.Mount(r) // /auth/* magic-link, email-password, OAuth, passkeys, TOTP, SAML
r.With(a.RequireAuth()).Get("/me", func(w http.ResponseWriter, r *http.Request) {
    user, _ := theauth.UserFromContext(r.Context())
    w.Write([]byte("hello " + user.Email))
})
http.ListenAndServe(":8080", r)
```

---

## Contents

- [Why theauth-go](#why-theauth-go)
- [Features at a glance](#features-at-a-glance)
- [Quick start](#quick-start)
- [MCP resource server](#mcp-resource-server)
- [Documentation](#documentation)
- [Examples](#examples)
- [Storage backends](#storage-backends)
- [Security](#security)
- [FAQ](#faq)
- [Contributing](#contributing)
- [License](#license)

---

## Why theauth-go

| | theauth-go | Auth0 | better-auth | Goth | Hydra |
|---|---|---|---|---|---|
| License | MIT | Proprietary | MIT | MIT | Apache 2.0 |
| Self-hosted | Yes | No | Yes | Yes | Yes |
| MCP authorization | Yes | No | No | No | No |
| FAPI 2.0 adjacent (PAR+JAR+DPoP) | Yes | Partial | No | No | Partial |
| DPoP-bound tokens | Yes | No | No | No | No |
| SBOM + Sigstore signed | Yes | No | No | No | No |
| Pluggable storage | Yes | No | Partial | No | Yes |
| Go-native, single import | Yes | No | No | Yes | No |

theauth-go is the first Go auth library where **OAuth 2.1**, **MCP authorization**, **agent identities**, and **revocable delegation chains** ship in a single `go get`. It drops into a `chi` or `net/http` server in under twenty lines.

---

## Features at a glance

<details>
<summary><strong>Expand full feature list</strong></summary>

### OAuth 2.1 grants

- Authorization code + PKCE S256 (mandatory)
- Refresh token with rotation + family revocation on replay
- `client_credentials` for service accounts and agents
- RFC 8693 token exchange: scope narrowing, duration tightening, actor chain capped at 3
- JWT bearer (RFC 7523)
- CIBA: RFC 9509 backchannel authentication (Poll + Ping modes)
- DPoP-bound access tokens (RFC 9449)
- PAR: Pushed Authorization Requests (RFC 9126)
- JAR: JWT-Secured Authorization Requests (RFC 9101)

### MCP authorization

- CIMD per MCP spec 2025-11-25
- `/.well-known/oauth-protected-resource` (RFC 9728)
- `mcpresource` SDK: zero-dependency module for MCP resource servers
- Actor-chain walking via AS introspection
- 401 with `WWW-Authenticate: Bearer` per RFC 6750 on failure

### Authentication

- Magic link sign-in
- Email + password with Argon2id (OWASP 2026 defaults, 12-char minimum)
- 12 OAuth providers: GitHub, Google, Microsoft, Discord, Facebook, Slack, GitLab, Bitbucket, Twitch, LinkedIn, X/Twitter, Apple
- WebAuthn passkeys: discoverable login, sign-count replay protection, NIST SP 800-63B single-factor-strong
- TOTP second factor with 10 single-use recovery codes and `pending_2fa` step-up state machine
- SAML 2.0 Service Provider (per-organization IdP binding, signed assertions only)

### Enterprise

- SCIM 2.0: Users and Groups CRUD, RFC 7644 PATCH, per-org isolation
- RBAC with closed permission catalog, seeded roles, `RequirePermission` middleware
- Organization multi-tenancy with `active_organization_id` session scope
- Audit logging: append-only, async, keyset pagination, pluggable SIEM sinks

### Storage

- **[storage/memory](storage/memory/)**: zero dependencies, for development and tests
- **[storage/postgres](storage/postgres/)**: production default, `pgx/v5` + `sqlc`
- **[storage/mysql](storage/mysql/)**: MySQL 8.x alternative
- **[storagetest](storagetest/)**: public contract test suite for custom backends

### Observability

- 10 OpenTelemetry spans across hot paths
- 10 Prometheus metrics (requests, errors, token issuances, latency histograms)
- Pluggable adapters: bring your own OTel exporter or Prometheus registry

### Security profile

- FAPI 2.0-adjacent: PAR + JAR + JWT-Bearer + DPoP
- Ed25519 JWT signing with 30-day JWKS rotation
- RFC 8707 audience binding (mandatory)
- RFC 9700 refresh-token rotation with replay detection
- RFC 7591 dynamic client registration with bearer-gated initial access tokens
- Per-IP and per-email rate limiting on every credential endpoint
- `HttpOnly`, `Secure`, `SameSite=Lax` cookies; only SHA-256 hash persisted

### Supply chain

- SBOM generated on every release
- Sigstore keyless signing via `cosign`
- SLSA-3 provenance attestation
- Verify with: `cosign verify-blob --certificate-identity-regexp=".*" --certificate-oidc-issuer="https://token.actions.githubusercontent.com" <artifact>`

</details>

---

## Quick start

**Requirements:** Go 1.25+

```bash
go get github.com/glincker/theauth-go
```

**Step 1 -- Create an auth instance with in-memory storage:**

```go
import (
    "github.com/glincker/theauth-go"
    "github.com/glincker/theauth-go/storage/memory"
)

a, err := theauth.New(theauth.Config{
    Storage: memory.New(),
    BaseURL: "http://localhost:8080", // used in magic-link emails
})
```

**Step 2 -- Mount routes and protect your API:**

```go
import "github.com/go-chi/chi/v5"

r := chi.NewRouter()
a.Mount(r) // wires /auth/* (magic-link, email-password, OAuth, passkeys, TOTP, SAML, MCP)

r.With(a.RequireAuth()).Get("/dashboard", func(w http.ResponseWriter, r *http.Request) {
    user, _ := theauth.UserFromContext(r.Context())
    fmt.Fprintf(w, "Welcome %s", user.Email)
})
```

**Step 3 -- Switch to Postgres for production:**

```go
import (
    "github.com/jackc/pgx/v5/pgxpool"
    "github.com/glincker/theauth-go/storage/postgres"
)

pool, _ := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
a, _ := theauth.New(theauth.Config{
    Storage: postgres.New(pool), // automatic schema migration on first run
    BaseURL: "https://myapp.com",
})
```

Full runnable example: [`examples/chi-app/`](./examples/chi-app)

---

## MCP resource server

The `mcpresource` module is a **zero-dependency** Go module for MCP resource servers. It does not pull in theauth core or any storage adapter.

```bash
go get github.com/glincker/theauth-go/mcpresource
```

```go
v := mcpresource.New(
    "https://mcp.example.com",
    mcpresource.WithJWKS("https://as.example.com/oauth/jwks"),
    mcpresource.WithIntrospection(
        "https://as.example.com/oauth/introspect",
        "mcp-client-id", "mcp-client-secret",
    ),
)

r := chi.NewRouter()
r.Use(v.Middleware) // JWT validation, audience check, actor-chain walk, revocation
r.Get("/tools/run", func(w http.ResponseWriter, r *http.Request) {
    p, _ := v.Principal(r.Context())
    // p.Subject (user), p.Actor (final agent), p.ActorChain (delegation path)
})
```

Full runnable example: [`examples/mcp-server/`](./examples/mcp-server)

---

## Documentation

| | |
|---|---|
| **[Getting Started](https://theauth.dev/go/getting-started/)** | Installation, quick start, choosing a storage backend |
| **[Concepts](https://theauth.dev/go/concepts/)** | OAuth 2.1, MCP, PAR/JAR, JWT-Bearer, CIBA, DPoP |
| **[Guides](https://theauth.dev/go/guides/)** | Add an OAuth provider, enable passkeys, OTel tracing, SIEM audit streaming |
| **[Reference](https://theauth.dev/go/reference/)** | Config, Storage, Errors, Metrics, Spans |
| **[Security](https://theauth.dev/go/security/)** | Threat model, SOC 2 mapping, GDPR data handling |
| **[Migrations](https://theauth.dev/go/migrations/)** | Version upgrade guides |
| **[Releases and verification](https://github.com/glincker/theauth-go/releases)** | `cosign verify-blob` command for SBOM and signed artifacts |

In-repo references:

| Document | Description |
|---|---|
| [AGENTS.md](docs/AGENTS.md) | Concise reference for AI coding assistants: patterns, anti-patterns, file map |
| [STABILITY.md](docs/STABILITY.md) | Public API surface, SemVer rules, Storage interface special rules |
| [CHANGELOG.md](CHANGELOG.md) | Per-release notable changes following Keep a Changelog |
| [SECURITY.md](SECURITY.md) | Vulnerability disclosure policy and contact |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Dev setup, test commands, commit convention, PR process |
| [MIGRATION.md](MIGRATION.md) | Step-by-step upgrade guides between major versions |

---

## Examples

| Example | What it shows |
|---|---|
| [`examples/chi-app/`](./examples/chi-app) | Magic links and email/password with chi |
| [`examples/echo-app/`](./examples/echo-app) | Drop-in with Echo |
| [`examples/gin-app/`](./examples/gin-app) | Drop-in with Gin |
| [`examples/stdlib-app/`](./examples/stdlib-app) | Pure `net/http`, no framework |
| [`examples/mcp-server/`](./examples/mcp-server) | MCP resource server using `mcpresource` middleware |
| [`examples/oauth-multi-provider/`](./examples/oauth-multi-provider) | GitHub + Google + Microsoft + Discord in one app |
| [`examples/observability-otel/`](./examples/observability-otel) | OTel tracing and span export |
| [`examples/observability-prom/`](./examples/observability-prom) | Prometheus metrics scrape |
| [`examples/webauthn-passkey/`](./examples/webauthn-passkey) | Passkey register and discoverable login |
| [`examples/totp-stepup/`](./examples/totp-stepup) | Password + TOTP step-up flow |
| [`examples/oauth-apple/`](./examples/oauth-apple) | Sign in with Apple (JWT client secret) |
| [`examples/oauth-gitlab/`](./examples/oauth-gitlab) | Sign in with GitLab (self-hosted or gitlab.com) |

Each example includes a `README`, `main.go`, `go.mod`, `docker-compose.yml`, `.env.example`, and `Makefile`.

---

## Storage backends

| Backend | Path | Use case |
|---|---|---|
| Memory | [storage/memory](storage/memory/) | Development, unit tests, zero deps |
| Postgres | [storage/postgres](storage/postgres/) | Production default, `pgx/v5` + `sqlc` |
| MySQL | [storage/mysql](storage/mysql/) | MySQL 8.x alternative |
| Contract suite | [storagetest](storagetest/) | Verify your own custom backend |

Bring your own storage backend by implementing the `Storage` interface and running the `storagetest` contract suite against it.

---

## Security

Please **do not** open a public GitHub issue for security vulnerabilities.

Report to **security@glincker.com** or use [GitHub Security Advisories](https://github.com/glincker/theauth-go/security/advisories/new).

See [SECURITY.md](SECURITY.md) for supported versions, disclosure policy, scope, and SLA targets.

---

## FAQ

**Is this production ready?**
Yes for v1.0+ surfaces (session auth, OAuth providers, RBAC, audit log),
covered by [STABILITY.md](docs/STABILITY.md)'s SemVer contract. v2.0's
OAuth 2.1 authorization server and agent-identity primitives are feature
complete as of v2.0.0. Check [CHANGELOG.md](CHANGELOG.md) for the
current release.

**How does it compare to Auth0, better-auth, or Ory Hydra?**
See the [comparison table](#why-theauth-go) above. The short version:
theauth-go is self-hosted like better-auth/Hydra but also ships MCP
authorization and FAPI 2.0-adjacent features (PAR+JAR+DPoP) that none of
the alternatives have.

**Does it support AI agent / MCP use cases specifically?**
Yes, this is one of the two things that differentiate it from every
other Go auth library. See the [MCP resource server](#mcp-resource-server)
section, and the agent-identity and delegation-chain docs.

**What databases are supported?**
Postgres and MySQL, plus an in-memory backend for tests. The `Storage`
interface is public, so custom backends are possible.

**Is it free and open source?**
Yes, MIT licensed, no paid tier gating any feature in this repository.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for dev setup, test commands, commit convention, and PR process.

Short version:

```bash
git clone https://github.com/glincker/theauth-go.git
cd theauth-go
go test -race ./...
go vet ./...
```

Open an issue first for anything beyond a typo or one-file fix.

---

## License

[MIT](LICENSE)

---

<div align="center">

*Built by the founder of [theSVG.org](https://thesvg.org).*

*A Product of **GLINR STUDIOS** | **A GLINCKER COMPANY***

</div>
