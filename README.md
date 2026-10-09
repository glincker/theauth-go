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

**[Website](https://theauth.dev)** &middot; **[Docs](https://docs.theauth.dev/go)** &middot; **[pkg.go.dev](https://pkg.go.dev/github.com/glincker/theauth-go/v2)** &middot; **[Packages](#packages)** &middot; **[theAuth for TypeScript](https://github.com/glincker/theauth)** (**[TypeScript packages](https://github.com/glincker/theauth#packages)**)

This is the Go SDK for [theAuth](https://theauth.dev), open-source auth for AI agents and humans. The TypeScript library lives in [glincker/theauth](https://github.com/glincker/theauth) and this repo is the Go counterpart. Both share one model: agents as identities, scoped permissions, delegation chains and an audit trail.

## Contents

- [Install](#install)
- [Packages](#packages)
- [Quick start: net/http and SQLite](#quick-start-nethttp-and-sqlite)
- [Quick start: agent identity and delegation](#quick-start-agent-identity-and-delegation)
- [Features](#features)
- [Storage backends](#storage-backends)
- [Stability](#stability)
- [FAQ](#faq)
- [Examples](#examples)

## Install

```bash
go get github.com/glincker/theauth-go/v2
go get github.com/glincker/theauth-go/storage/sqlite   # optional, embedded SQLite backend
```

The module path ends in `/v2`. The first resolvable v2 tag is `v2.6.0`, and the old path without `/v2` is frozen at `v1.0.0`. See [Migrating to /v2](https://docs.theauth.dev/go/migrations/to-v2-module-path).

## Packages

One Go module at the root plus three nested modules (`mcpresource`, `storage/sqlite`, `audit/sinks/otlp`) that carry their own dependencies. Everything else is a package inside the root module. The matching TypeScript packages are listed in the [theAuth README](https://github.com/glincker/theauth#packages).

| Package | Purpose | pkg.go.dev | Source | Docs |
|---|---|---|---|---|
| **Core** | | | | |
| `github.com/glincker/theauth-go/v2` | Root module `theauth`: server, sessions, OAuth 2.1 authorization server, agent identity, MCP authorization | [pkg.go.dev](https://pkg.go.dev/github.com/glincker/theauth-go/v2) | [repo root](https://github.com/glincker/theauth-go) | [docs](https://docs.theauth.dev/go/getting-started/overview) |
| `github.com/glincker/theauth-go/v2/admin` | Shared helpers for the `/admin/v1` HTTP surface | [pkg.go.dev](https://pkg.go.dev/github.com/glincker/theauth-go/v2/admin) | [admin](https://github.com/glincker/theauth-go/tree/main/admin) |  |
| `github.com/glincker/theauth-go/v2/crypto` | Password hashing and crypto primitives | [pkg.go.dev](https://pkg.go.dev/github.com/glincker/theauth-go/v2/crypto) | [crypto](https://github.com/glincker/theauth-go/tree/main/crypto) |  |
| `github.com/glincker/theauth-go/v2/email` | `Sender` interface and email delivery helpers | [pkg.go.dev](https://pkg.go.dev/github.com/glincker/theauth-go/v2/email) | [email](https://github.com/glincker/theauth-go/tree/main/email) |  |
| `github.com/glincker/theauth-go/v2/policy` | Small dependency-free authorization (policy) engine | [pkg.go.dev](https://pkg.go.dev/github.com/glincker/theauth-go/v2/policy) | [policy](https://github.com/glincker/theauth-go/tree/main/policy) | [docs](https://docs.theauth.dev/go/guides/policy-engine) |
| `github.com/glincker/theauth-go/v2/clientauth` | Let any Go CLI authenticate against a theauth-go server (device login) | [pkg.go.dev](https://pkg.go.dev/github.com/glincker/theauth-go/v2/clientauth) | [clientauth](https://github.com/glincker/theauth-go/tree/main/clientauth) | [docs](https://docs.theauth.dev/go/guides/cli-login) |
| `github.com/glincker/theauth-go/mcpresource` | Separate module: one-import resource server SDK for MCP servers | [pkg.go.dev](https://pkg.go.dev/github.com/glincker/theauth-go/mcpresource) | [mcpresource](https://github.com/glincker/theauth-go/tree/main/mcpresource) | [docs](https://docs.theauth.dev/go/concepts/resource-server) |
| **Storage** | | | | |
| `github.com/glincker/theauth-go/v2/storage` | `Storage` interface and capability re-exports | [pkg.go.dev](https://pkg.go.dev/github.com/glincker/theauth-go/v2/storage) | [storage](https://github.com/glincker/theauth-go/tree/main/storage) | [docs](https://docs.theauth.dev/go/reference/storage) |
| `github.com/glincker/theauth-go/v2/storage/memory` | In-process storage, for tests and demos | [pkg.go.dev](https://pkg.go.dev/github.com/glincker/theauth-go/v2/storage/memory) | [storage/memory](https://github.com/glincker/theauth-go/tree/main/storage/memory) | [docs](https://docs.theauth.dev/go/getting-started/storage-backends) |
| `github.com/glincker/theauth-go/storage/sqlite` | Separate module: embedded SQLite backend | [pkg.go.dev](https://pkg.go.dev/github.com/glincker/theauth-go/storage/sqlite) | [storage/sqlite](https://github.com/glincker/theauth-go/tree/main/storage/sqlite) | [docs](https://docs.theauth.dev/go/guides/sqlite-storage) |
| `github.com/glincker/theauth-go/v2/storage/postgres` | PostgreSQL backend | [pkg.go.dev](https://pkg.go.dev/github.com/glincker/theauth-go/v2/storage/postgres) | [storage/postgres](https://github.com/glincker/theauth-go/tree/main/storage/postgres) | [docs](https://docs.theauth.dev/go/guides/postgres-mysql-storage) |
| `github.com/glincker/theauth-go/v2/storage/mysql` | MySQL 8.x backend | [pkg.go.dev](https://pkg.go.dev/github.com/glincker/theauth-go/v2/storage/mysql) | [storage/mysql](https://github.com/glincker/theauth-go/tree/main/storage/mysql) | [docs](https://docs.theauth.dev/go/guides/postgres-mysql-storage) |
| `github.com/glincker/theauth-go/v2/storagetest` | Public contract test suite for custom storage backends | [pkg.go.dev](https://pkg.go.dev/github.com/glincker/theauth-go/v2/storagetest) | [storagetest](https://github.com/glincker/theauth-go/tree/main/storagetest) | [docs](https://docs.theauth.dev/go/guides/custom-storage-backend) |
| `github.com/glincker/theauth-go/v2/otp` | Email and SMS one-time codes with cooldown and lockout | [pkg.go.dev](https://pkg.go.dev/github.com/glincker/theauth-go/v2/otp) | [otp](https://github.com/glincker/theauth-go/tree/main/otp) | [docs](./docs/otp.md) |
| `github.com/glincker/theauth-go/v2/openapi` | OpenAPI 3.1 generator for a mounted chi router | [pkg.go.dev](https://pkg.go.dev/github.com/glincker/theauth-go/v2/openapi) | [openapi](https://github.com/glincker/theauth-go/tree/main/openapi) | [docs](./docs/cli.md) |
| **Audit sinks** | | | | |
| `github.com/glincker/theauth-go/audit/sinks/otlp` | Separate module: export audit events over OTLP | not yet indexed | [audit/sinks/otlp](https://github.com/glincker/theauth-go/tree/main/audit/sinks/otlp) |  |
| `github.com/glincker/theauth-go/v2/audit/sinks/splunkhec` | Forward audit batches to Splunk HEC | [pkg.go.dev](https://pkg.go.dev/github.com/glincker/theauth-go/v2/audit/sinks/splunkhec) | [audit/sinks/splunkhec](https://github.com/glincker/theauth-go/tree/main/audit/sinks/splunkhec) | [docs](https://docs.theauth.dev/go/guides/audit-log-splunk) |
| `github.com/glincker/theauth-go/v2/audit/sinks/webhook` | POST audit events to a webhook | [pkg.go.dev](https://pkg.go.dev/github.com/glincker/theauth-go/v2/audit/sinks/webhook) | [audit/sinks/webhook](https://github.com/glincker/theauth-go/tree/main/audit/sinks/webhook) |  |
| **OAuth and OIDC providers** | | | | |
| `github.com/glincker/theauth-go/v2/provider` | Namespace root for the built-in OAuth 2.0 / OIDC providers | [pkg.go.dev](https://pkg.go.dev/github.com/glincker/theauth-go/v2/provider) | [provider](https://github.com/glincker/theauth-go/tree/main/provider) | [docs](https://docs.theauth.dev/go/guides/add-oauth-provider) |
| `github.com/glincker/theauth-go/v2/provider/apple` | Sign In with Apple login provider | [pkg.go.dev](https://pkg.go.dev/github.com/glincker/theauth-go/v2/provider/apple) | [provider/apple](https://github.com/glincker/theauth-go/tree/main/provider/apple) |  |
| `github.com/glincker/theauth-go/v2/provider/bitbucket` | Bitbucket Cloud login provider | [pkg.go.dev](https://pkg.go.dev/github.com/glincker/theauth-go/v2/provider/bitbucket) | [provider/bitbucket](https://github.com/glincker/theauth-go/tree/main/provider/bitbucket) |  |
| `github.com/glincker/theauth-go/v2/provider/discord` | Discord login provider | [pkg.go.dev](https://pkg.go.dev/github.com/glincker/theauth-go/v2/provider/discord) | [provider/discord](https://github.com/glincker/theauth-go/tree/main/provider/discord) |  |
| `github.com/glincker/theauth-go/v2/provider/facebook` | Facebook (Meta) login provider | [pkg.go.dev](https://pkg.go.dev/github.com/glincker/theauth-go/v2/provider/facebook) | [provider/facebook](https://github.com/glincker/theauth-go/tree/main/provider/facebook) |  |
| `github.com/glincker/theauth-go/v2/provider/github` | GitHub login provider | [pkg.go.dev](https://pkg.go.dev/github.com/glincker/theauth-go/v2/provider/github) | [provider/github](https://github.com/glincker/theauth-go/tree/main/provider/github) |  |
| `github.com/glincker/theauth-go/v2/provider/gitlab` | GitLab login provider | [pkg.go.dev](https://pkg.go.dev/github.com/glincker/theauth-go/v2/provider/gitlab) | [provider/gitlab](https://github.com/glincker/theauth-go/tree/main/provider/gitlab) |  |
| `github.com/glincker/theauth-go/v2/provider/google` | Google login provider | [pkg.go.dev](https://pkg.go.dev/github.com/glincker/theauth-go/v2/provider/google) | [provider/google](https://github.com/glincker/theauth-go/tree/main/provider/google) |  |
| `github.com/glincker/theauth-go/v2/provider/linkedin` | LinkedIn login provider | [pkg.go.dev](https://pkg.go.dev/github.com/glincker/theauth-go/v2/provider/linkedin) | [provider/linkedin](https://github.com/glincker/theauth-go/tree/main/provider/linkedin) |  |
| `github.com/glincker/theauth-go/v2/provider/microsoft` | Microsoft Entra login provider | [pkg.go.dev](https://pkg.go.dev/github.com/glincker/theauth-go/v2/provider/microsoft) | [provider/microsoft](https://github.com/glincker/theauth-go/tree/main/provider/microsoft) |  |
| `github.com/glincker/theauth-go/v2/provider/oidc` | Generic OIDC login provider | [pkg.go.dev](https://pkg.go.dev/github.com/glincker/theauth-go/v2/provider/oidc) | [provider/oidc](https://github.com/glincker/theauth-go/tree/main/provider/oidc) | [docs](https://docs.theauth.dev/go/guides/add-oauth-provider) |
| `github.com/glincker/theauth-go/v2/provider/generic` | Table-driven OAuth providers (Spotify, Dropbox, Zoom, Kakao, Naver, Patreon, Box, Salesforce, Figma, Codeberg) | [pkg.go.dev](https://pkg.go.dev/github.com/glincker/theauth-go/v2/provider/generic) | [provider/generic](https://github.com/glincker/theauth-go/tree/main/provider/generic) | [docs](./docs/provider-catalog.md) |
| `github.com/glincker/theauth-go/v2/provider/slack` | Slack login provider | [pkg.go.dev](https://pkg.go.dev/github.com/glincker/theauth-go/v2/provider/slack) | [provider/slack](https://github.com/glincker/theauth-go/tree/main/provider/slack) |  |
| `github.com/glincker/theauth-go/v2/provider/twitch` | Twitch login provider | [pkg.go.dev](https://pkg.go.dev/github.com/glincker/theauth-go/v2/provider/twitch) | [provider/twitch](https://github.com/glincker/theauth-go/tree/main/provider/twitch) |  |
| `github.com/glincker/theauth-go/v2/provider/x` | X (formerly Twitter) login provider | [pkg.go.dev](https://pkg.go.dev/github.com/glincker/theauth-go/v2/provider/x) | [provider/x](https://github.com/glincker/theauth-go/tree/main/provider/x) |  |
| **Commands** | | | | |
| `github.com/glincker/theauth-go/v2/cmd/theauth-go` | Developer CLI: secret generation and OpenAPI output | [pkg.go.dev](https://pkg.go.dev/github.com/glincker/theauth-go/v2/cmd/theauth-go) | [cmd/theauth-go](https://github.com/glincker/theauth-go/tree/main/cmd/theauth-go) | [docs](./docs/cli.md) |
| `github.com/glincker/theauth-go/v2/cmd/theauth-doctor` | Security doctor CLI | [pkg.go.dev](https://pkg.go.dev/github.com/glincker/theauth-go/v2/cmd/theauth-doctor) | [cmd/theauth-doctor](https://github.com/glincker/theauth-go/tree/main/cmd/theauth-doctor) | [docs](https://docs.theauth.dev/go/guides/security-doctor) |
| `github.com/glincker/theauth-go/v2/cmd/theauth-migrate` | Migration CLI for importing users | [pkg.go.dev](https://pkg.go.dev/github.com/glincker/theauth-go/v2/cmd/theauth-migrate) | [cmd/theauth-migrate](https://github.com/glincker/theauth-go/tree/main/cmd/theauth-migrate) | [docs](https://docs.theauth.dev/go/migrations/migration-guide) |
| `github.com/glincker/theauth-go/v2/cmd/theauth-migrate/auth0` | Auth0 user-pool export reader | [pkg.go.dev](https://pkg.go.dev/github.com/glincker/theauth-go/v2/cmd/theauth-migrate/auth0) | [cmd/theauth-migrate/auth0](https://github.com/glincker/theauth-go/tree/main/cmd/theauth-migrate/auth0) | [docs](https://docs.theauth.dev/go/guides/migrate-from-auth0) |
| `github.com/glincker/theauth-go/v2/cmd/theauth-migrate/cognito` | AWS Cognito user-pool export reader | [pkg.go.dev](https://pkg.go.dev/github.com/glincker/theauth-go/v2/cmd/theauth-migrate/cognito) | [cmd/theauth-migrate/cognito](https://github.com/glincker/theauth-go/tree/main/cmd/theauth-migrate/cognito) | [docs](https://docs.theauth.dev/go/guides/migrate-from-cognito) |

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

Mounting: `a.Handler()` returns a plain `http.Handler` for `net/http`'s `ServeMux` and keeps the routes at their configured paths (`/auth/...`, `/oauth/...`), so no `http.StripPrefix` is needed. With chi, call `a.Mount(r)` on your router instead. Both register the same routes.

## Quick start: agent identity and delegation

Give an agent its own credential, then let it act for a user with a narrower scope. This needs `Config.AuthorizationServer` (which requires a 32 byte `EncryptionKey`) and `Config.AgentIdentity`, on a storage backend with agent identity support (memory, Postgres or MySQL; not SQLite). `RegisterAgent` creates the agent and, because `Resource` is set, a delegation grant from the user to the agent in one call.

```go
package main

import (
	"context"
	"log"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/storage/memory"
)

func main() {
	ctx := context.Background()
	a, err := theauth.New(theauth.Config{
		Storage:       memory.New(),
		BaseURL:       "https://as.example.com",
		EncryptionKey: []byte("0123456789abcdef0123456789abcdef"), // 32 bytes, load from your secrets manager
		AuthorizationServer: &theauth.AuthorizationServerConfig{
			Issuer: "https://as.example.com",
			Resources: []theauth.ProtectedResource{
				{Identifier: "https://api.example.com", Scopes: []string{"read", "write"}},
			},
		},
		AgentIdentity: &theauth.AgentConfig{},
	})
	if err != nil {
		log.Fatal(err)
	}
	defer a.Close()

	// The human who owns the agent. In a real app this is a signed-in user.
	user, err := a.UserByID(ctx, ownerID)
	if err != nil {
		log.Fatal(err)
	}

	// 1. Create the agent and a delegation grant for "read" on one resource.
	reg, err := a.RegisterAgent(ctx, theauth.RegisterAgentInput{
		OwnerID:  user.ID,
		Name:     "report-bot",
		Scope:    []string{"read"},
		Resource: "https://api.example.com",
	})
	if err != nil {
		log.Fatal(err)
	}
	// reg.Secret.ClientID and reg.Secret.Secret are the agent's credential.
	// The secret is shown once and only its Argon2id hash is stored.

	// 2. The agent authenticates as itself (client credentials).
	self, err := a.ClientCredentialsToken(ctx, theauth.TokenRequest{
		GrantType:    "client_credentials",
		ClientID:     reg.Secret.ClientID,
		ClientSecret: reg.Secret.Secret,
		Resource:     "https://api.example.com",
		Scope:        []string{"read"},
	})
	if err != nil {
		log.Fatal(err)
	}
	_ = self.AccessToken // sub is "agent:<id>"

	// 3. The agent trades a user's access token for a delegated one
	// (RFC 8693). The result carries the user as sub and the agent in act.
	delegated, err := a.ExchangeToken(ctx, theauth.TokenExchangeRequest{
		ClientID:         reg.Secret.ClientID,
		ClientSecret:     reg.Secret.Secret,
		SubjectToken:     userAccessToken, // issued to the user by this authorization server
		SubjectTokenType: "urn:ietf:params:oauth:token-type:access_token",
		Resource:         "https://api.example.com",
		Scope:            []string{"read"},
	})
	if err != nil {
		log.Fatal(err)
	}
	log.Println("delegated token expires in", delegated.ExpiresIn, "seconds")
}
```

`ownerID` and `userAccessToken` stand in for values from your sign-in flow (the user's ULID and an access token the authorization server issued to that user). Revoke access at any point with `RevokeDelegation`, `SuspendAgent` or `RevokeAgent`; resource servers see the change on their next introspection. Details: [Agent identity and revocation](https://docs.theauth.dev/go/concepts/agent-identity), [Agent delegation](https://docs.theauth.dev/go/guides/agent-delegation) and [Authorization server](https://docs.theauth.dev/go/concepts/authorization-server).

## Features

| Area | What you get | Docs |
|---|---|---|
| Sign-in | Email and password (Argon2id, 12 character minimum), magic links, 12 OAuth login providers, generic OIDC | [Add an OAuth provider](https://docs.theauth.dev/go/guides/add-oauth-provider) |
| Second factors | WebAuthn passkeys with discoverable login, TOTP with recovery codes, step-up with `RequireRecentAuth` | [Enable passkeys](https://docs.theauth.dev/go/guides/webauthn-passkeys) |
| Sessions | Opaque server-side sessions, session list and revoke, idle timeout | [Configuration](https://docs.theauth.dev/go/reference/configuration) |
| API tokens and CLIs | Scoped tokens with `RequireAbility`, RFC 8628 device login via the `clientauth` package | [API tokens](https://docs.theauth.dev/go/guides/api-tokens), [CLI login](https://docs.theauth.dev/go/guides/cli-login) |
| OAuth 2.1 server | Authorization code with PKCE, refresh rotation, `client_credentials`, token exchange, CIBA, PAR, JAR, DPoP | [OAuth 2.1 primer](https://docs.theauth.dev/go/concepts/oauth21-primer), [Authorization server](https://docs.theauth.dev/go/concepts/authorization-server) |
| Token policy, RAR and ID-JAG | Per-client signing algorithm (EdDSA, ES256, RS256) and opaque access tokens, RFC 9396 `authorization_details` end to end, and ID-JAG issue and redeem over token exchange and jwt-bearer | [Token policy](./docs/access-token-policy.md), [RAR](./docs/rich-authorization-requests.md), [ID-JAG](./docs/id-jag.md) |
| Multi-replica and abuse controls | Pluggable rate limiter, DPoP replay cache and CIMD cache (memory, SQL, Redis or your own), per-IP and per-client limits and an Argon2id concurrency cap on the OAuth endpoints | [Pluggable stores](./docs/pluggable-stores.md), [Endpoint limits](./docs/oauth-endpoint-limits.md) |
| Browserless OAuth | RFC 8628 device authorization grant on the authorization server with a themable verification page, plus scoped one-time registration tokens for agents | [Device grant](./docs/device-authorization.md), [Registration tokens](./docs/registration-tokens.md) |
| One-time codes | Email and SMS OTP with pluggable senders (Twilio built in), resend cooldown, attempt limit, lockout, constant-time compare | [OTP](./docs/otp.md) |
| More sign-in providers | Table-driven catalog of 10 more OAuth providers, custom specs, and OIDC discovery overrides | [Provider catalog](./docs/provider-catalog.md) |
| Developer CLI and OpenAPI | `theauth-go secret` and `theauth-go openapi`, plus `openapi.Generate` for your own router | [CLI](./docs/cli.md) |
| MCP and agents | MCP authorization (protected resource metadata, CIMD), agent identities with delegation, `mcpresource` SDK module | [MCP authorization](https://docs.theauth.dev/go/concepts/mcp-authorization), [Resource server](https://docs.theauth.dev/go/concepts/resource-server) |
| Enterprise | SAML 2.0 SSO, SCIM 2.0, organizations, RBAC, append-only audit log with SIEM sinks | [Splunk audit streaming](https://docs.theauth.dev/go/guides/audit-log-splunk), [Threat model](https://docs.theauth.dev/go/security/threat-model) |
| Policy | Authorization policy engine | [Policy engine](https://docs.theauth.dev/go/guides/policy-engine) |
| Observability | OpenTelemetry spans, Prometheus metrics | [OpenTelemetry tracing](https://docs.theauth.dev/go/guides/opentelemetry-tracing), [Metrics](https://docs.theauth.dev/go/reference/metrics) |
| Supply chain | SBOM and Sigstore signed release artifacts, SLSA 3 provenance | [Releases and verification](https://docs.theauth.dev/go/security/releases) |

## Running more than one replica

Rate limits, DPoP replay records and the CIMD cache are per process by default. Share them through the database you already have:

```go
db := stdlib.OpenDBFromPool(pool) // pgx stdlib
kvStore, _ := sqlkv.New(db, sqlkv.Postgres)
_ = kvStore.EnsureSchema(ctx)

auth, _ := theauth.New(theauth.Config{
    // ...
    Stores: kv.FromCache(kvStore), // or kv/redis, or your own kv.RateLimiter / kv.ReplayCache / kv.Cache
})
```

Details and the Redis adapter are in [docs/pluggable-stores.md](./docs/pluggable-stores.md).

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
| OAuth device grant (RFC 8628) and registration tokens | Yes | No | Yes | Yes |
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

Runnable apps live in [`examples/`](./examples), each with its own `go.mod` and a short README. More in the [example apps guide](https://docs.theauth.dev/go/getting-started/example-apps).

| Area | Examples |
|---|---|
| Frameworks | [`single-binary-sqlite`](./examples/single-binary-sqlite), [`chi-app`](./examples/chi-app), [`gin-app`](./examples/gin-app), [`echo-app`](./examples/echo-app), [`stdlib-app`](./examples/stdlib-app) |
| OAuth providers | [`oauth-multi-provider`](./examples/oauth-multi-provider), [`oauth-apple`](./examples/oauth-apple), [`oauth-bitbucket`](./examples/oauth-bitbucket), [`oauth-facebook`](./examples/oauth-facebook), [`oauth-gitlab`](./examples/oauth-gitlab), [`oauth-linkedin`](./examples/oauth-linkedin), [`oauth-slack`](./examples/oauth-slack), [`oauth-twitch`](./examples/oauth-twitch), [`oauth-x`](./examples/oauth-x) |
| Second factors | [`webauthn-passkey`](./examples/webauthn-passkey), [`totp-stepup`](./examples/totp-stepup) |
| Agents and CLIs | [`mcp-server`](./examples/mcp-server), [`cli-login`](./examples/cli-login) |
| Operations | [`doctor-admin`](./examples/doctor-admin), [`observability-otel`](./examples/observability-otel), [`observability-prom`](./examples/observability-prom) |

## Links

- [Documentation](https://docs.theauth.dev/go) and [API reference on pkg.go.dev](https://pkg.go.dev/github.com/glincker/theauth-go/v2)
- [CHANGELOG](CHANGELOG.md), [STABILITY](https://docs.theauth.dev/go/reference/stability), [ROADMAP](docs/ROADMAP.md)
- [Security policy](.github/SECURITY.md): report vulnerabilities privately, not in public issues
- [Contributing](.github/CONTRIBUTING.md), [Discussions](https://github.com/glincker/theauth-go/discussions), [Discord](https://discord.gg/Ar5pcaZB99)
- [AGENTS.md](docs/AGENTS.md) and [llms.txt](llms.txt) for AI coding assistants
- [License: MIT](LICENSE)

## Made by GLINCKER, a GLINR STUDIOS company

theAuth is built and maintained in the open by [GLINCKER](https://glincker.com), the open-source division of [GLINR STUDIOS](https://glinr.com). Founder: [thegdsks.com](https://thegdsks.com). The TypeScript library is [glincker/theauth](https://github.com/glincker/theauth).

| Partner project | What it is | Site | Source |
|---|---|---|---|
| **LevelRail** | Self-hosted deployment platform: push to git, get a running app. | [levelrail.com](https://levelrail.com) | [glincker/levelrail](https://github.com/glincker/levelrail) |
| **theSVG** | Open-source brand SVG icons. | [thesvg.org](https://thesvg.org) | [glincker/thesvg](https://github.com/glincker/thesvg) |
| **GLINUI** | Open-source liquid glass UI components for React. theauth.dev is designed with it. | [glinui.com](https://glinui.com) | [glincker/glinui](https://github.com/glincker/glinui) |
