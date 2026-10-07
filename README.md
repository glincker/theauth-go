# theauth-go

**Authentication and authorization library for Go.** Mount it into your own `net/http` or `chi` server for password, magic link, OAuth 2.1 / OIDC login providers, passkeys (WebAuthn), TOTP, SAML SSO, SCIM, scoped API tokens, RFC 8628 device login for CLIs, agent identity, MCP authorization and a policy engine. Your data stays in your own database: memory, SQLite, Postgres or MySQL. MIT licensed, no hosted service.

[![Go Reference](https://pkg.go.dev/badge/github.com/glincker/theauth-go/v2.svg)](https://pkg.go.dev/github.com/glincker/theauth-go/v2)
[![Go Report Card](https://goreportcard.com/badge/github.com/glincker/theauth-go/v2)](https://goreportcard.com/report/github.com/glincker/theauth-go/v2)
[![Release](https://img.shields.io/github/v/release/glincker/theauth-go?label=latest)](https://github.com/glincker/theauth-go/releases)
[![CI](https://github.com/glincker/theauth-go/actions/workflows/ci.yml/badge.svg)](https://github.com/glincker/theauth-go/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/glincker/theauth-go/branch/main/graph/badge.svg)](https://codecov.io/gh/glincker/theauth-go)
[![Discord](https://img.shields.io/discord/829168897080557579?style=flat-square&logo=discord&logoColor=white&label=discord&color=5865F2)](https://discord.gg/Ar5pcaZB99)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![SLSA 3](https://slsa.dev/images/gh-badge-level3.svg)](https://github.com/glincker/theauth-go/releases)
[![Discord](https://img.shields.io/discord/829168897080557579?style=flat-square&logo=discord&logoColor=white&label=discord&color=5865F2)](https://discord.gg/Ar5pcaZB99)

Website: **[theauth.dev](https://theauth.dev)** | Documentation: **[docs.theauth.dev/go](https://docs.theauth.dev/go)**

Part of [theAuth](https://theauth.dev), open-source auth for AI agents and humans. Docs: [docs.theauth.dev](https://docs.theauth.dev).

## Install

```bash
go get github.com/glincker/theauth-go/v2
go get github.com/glincker/theauth-go/storage/sqlite   # optional, embedded SQLite backend
```

The module path ends in `/v2`. The first resolvable v2 tag is `v2.6.0`, and the old path without `/v2` is frozen at `v1.0.0`. See [Migrating to /v2](https://docs.theauth.dev/go/migrations/to-v2-module-path).

## Quick start: net/http and SQLite

A complete server with sign-up, sign-in, magic links, sessions and one protected route, stored in a single SQLite file. Errors are checked; paste it into a `main` package. The `storage/sqlite` module needs Go 1.26.

```go
package main

import (
	"context"
	"database/sql"
	"log"
	"net/http"

	"github.com/glincker/theauth-go/v2"
	sqlitestore "github.com/glincker/theauth-go/storage/sqlite"
	_ "modernc.org/sqlite"
)

func main() {
	ctx := context.Background()
	db, err := sql.Open("sqlite", "file:app.db?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_txlock=immediate")
	if err != nil {
		log.Fatal(err)
	}
	if err := sqlitestore.Migrate(ctx, db); err != nil {
		log.Fatal(err)
	}
	store, err := sqlitestore.New(db)
	if err != nil {
		log.Fatal(err)
	}

	a, err := theauth.New(theauth.Config{CoreStorage: store, BaseURL: "http://localhost:8080"})
	if err != nil {
		log.Fatal(err)
	}
	defer a.Close()

	mux := http.NewServeMux()
	mux.Handle("/auth/", a.Handler()) // sign-up, sign-in, magic link, sessions
	mux.Handle("GET /me", a.RequireAuth()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, _ := theauth.UserFromContext(r.Context())
		w.Write([]byte("hello " + user.Email))
	})))
	log.Fatal(http.ListenAndServe(":8080", mux))
}
```

For Postgres, chi or a runnable CLI with API tokens and device login, see [`examples/single-binary-sqlite`](./examples/single-binary-sqlite) and the [Quick Start](https://docs.theauth.dev/go/getting-started/quick-start).

## Features

| Area | What you get | Docs |
|---|---|---|
| Sign-in | Email and password (Argon2id, 12 character minimum), magic links, 12 OAuth login providers, generic OIDC | [Add an OAuth provider](https://docs.theauth.dev/go/guides/add-oauth-provider) |
| Second factors | WebAuthn passkeys with discoverable login, TOTP with recovery codes, step-up with `RequireRecentAuth` | [Enable passkeys](https://docs.theauth.dev/go/guides/webauthn-passkeys) |
| Sessions | Opaque server-side sessions, session list and revoke, idle timeout | [Configuration](https://docs.theauth.dev/go/reference/configuration) |
| API tokens and CLIs | Scoped tokens with `RequireAbility`, RFC 8628 device login via the `clientauth` package | [API tokens](https://docs.theauth.dev/go/guides/api-tokens), [CLI login](https://docs.theauth.dev/go/guides/cli-login) |
| OAuth 2.1 server | Authorization code with PKCE, refresh rotation, `client_credentials`, token exchange, CIBA, PAR, JAR, DPoP | [OAuth 2.1 primer](https://docs.theauth.dev/go/concepts/oauth21-primer), [Authorization server](https://docs.theauth.dev/go/concepts/authorization-server) |
| MCP and agents | MCP authorization (protected resource metadata, CIMD), agent identities with delegation, `mcpresource` SDK module | [MCP authorization](https://docs.theauth.dev/go/concepts/mcp-authorization), [Resource server](https://docs.theauth.dev/go/concepts/resource-server) |
| Enterprise | SAML 2.0 SSO, SCIM 2.0, organizations, RBAC, append-only audit log with SIEM sinks | [Splunk audit streaming](https://docs.theauth.dev/go/guides/audit-log-splunk), [Threat model](https://docs.theauth.dev/go/security/threat-model) |
| Policy | Authorization policy engine | [Policy engine](https://docs.theauth.dev/go/guides/policy-engine) |
| Observability | OpenTelemetry spans, Prometheus metrics | [OpenTelemetry tracing](https://docs.theauth.dev/go/guides/opentelemetry-tracing), [Metrics](https://docs.theauth.dev/go/reference/metrics) |
| Supply chain | SBOM and Sigstore signed release artifacts, SLSA 3 provenance | [Releases and verification](https://docs.theauth.dev/go/security/releases) |

## Storage backends

Persistence is split into small capability interfaces, and `New` fails at startup if a feature you enabled has no matching capability. Full matrix: [Capability interfaces](https://docs.theauth.dev/go/concepts/capability-interfaces).

| Capability | memory | sqlite | postgres | mysql |
|---|---|---|---|---|
| Users, sessions, magic links, passwords | Yes | Yes | Yes | Yes |
| OAuth accounts, passkeys, TOTP, audit log | Yes | Yes | Yes | Yes |
| Scoped API tokens, device grant, session management | Yes | Yes | Yes | Yes |
| Organizations, SAML, SCIM, RBAC | Yes | No | Yes | Yes |
| OAuth 2.1 authorization server, agent identity | Yes | No | Yes | Yes |
| CIBA backchannel auth | Yes | No | Yes | No |
| Durable JWT-bearer `jti` replay, policy engine storage | Yes | No | No | No |

Postgres and MySQL implement the newer token, device, session and throttle capabilities and pass the new `storagetest` suites against live PostgreSQL 16 and MySQL 8. The older shared contract gate for those two adapters is still off in CI because some older subtests fail, so treat their support for the newer features as newly added. You can write your own backend and verify it with the public [`storagetest`](./storagetest) suite.

## Stability

Packages and APIs that were Stable before v2.6 keep their SemVer guarantees. Among the additions in v2.6, only the storage capability split, `Handler()` and `Config.PathPrefix` are Stable. Experimental: `storage/sqlite`, `clientauth`, `policy`, the agent identity and revocation APIs, `Doctor`, `Config.ProviderResolver` and the new optional storage capabilities. Experimental APIs may change in a minor release. The SemVer rules and the list of stable packages are in [STABILITY.md](https://docs.theauth.dev/go/reference/stability).

## FAQ

**Does theauth-go work without Postgres?**
Yes. Use `storage/sqlite` for a single static binary with one database file, `storage/memory` for tests, or MySQL. SQLite has no organizations, SAML, SCIM, RBAC or OAuth authorization server.

**How do I add passkeys to a Go app?**
Set `Config.WebAuthn` and use a storage backend that implements `WebAuthnStorage` (all four built in backends do). Register and login routes are then mounted under your auth handler. See the [passkeys guide](https://docs.theauth.dev/go/guides/webauthn-passkeys) and [`examples/webauthn-passkey`](./examples/webauthn-passkey).

**Does it support MCP authorization?**
Yes. The library can act as the OAuth 2.1 authorization server and publishes protected resource metadata. The separate zero dependency `mcpresource` module validates tokens inside an MCP resource server. See [MCP authorization](https://docs.theauth.dev/go/concepts/mcp-authorization) and [`examples/mcp-server`](./examples/mcp-server).

**How do I migrate from Auth0 or Cognito?**
Follow [Migrate from Auth0](https://docs.theauth.dev/go/guides/migrate-from-auth0) or [Migrate from Cognito](https://docs.theauth.dev/go/guides/migrate-from-cognito). Coming from hand-rolled sessions: [Migrate from hand-rolled sessions](https://docs.theauth.dev/go/guides/migrate-from-hand-rolled-sessions).

**Which Go versions are supported?**
The root module declares Go 1.25. `storage/sqlite` is a separate module and needs Go 1.26.

**Is it a hosted service?**
No. It is a library you run inside your own process, under the MIT license.

## Examples

Runnable apps live in [`examples/`](./examples): [`single-binary-sqlite`](./examples/single-binary-sqlite), [`chi-app`](./examples/chi-app), [`gin-app`](./examples/gin-app), [`echo-app`](./examples/echo-app), [`stdlib-app`](./examples/stdlib-app), [`webauthn-passkey`](./examples/webauthn-passkey), [`totp-stepup`](./examples/totp-stepup), [`oauth-multi-provider`](./examples/oauth-multi-provider), [`mcp-server`](./examples/mcp-server), [`cli-login`](./examples/cli-login), [`observability-otel`](./examples/observability-otel) and [`observability-prom`](./examples/observability-prom). More in the [example apps guide](https://docs.theauth.dev/go/getting-started/example-apps).

## Links

- [Documentation](https://docs.theauth.dev/go) and [API reference on pkg.go.dev](https://pkg.go.dev/github.com/glincker/theauth-go/v2)
- [CHANGELOG](CHANGELOG.md), [STABILITY](https://docs.theauth.dev/go/reference/stability), [ROADMAP](docs/ROADMAP.md)
- [Security policy](.github/SECURITY.md): report vulnerabilities privately, not in public issues
- [Contributing](.github/CONTRIBUTING.md), [Discussions](https://github.com/glincker/theauth-go/discussions), [Discord](https://discord.gg/Ar5pcaZB99)
- [AGENTS.md](docs/AGENTS.md) and [llms.txt](llms.txt) for AI coding assistants
- [License: MIT](LICENSE)

Built by the founder of [theSVG.org](https://thesvg.org). A product of GLINR STUDIOS.
