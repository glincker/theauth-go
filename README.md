# theauth-go

A Go library that adds sign-in and an OAuth 2.1 authorization server to your own server, for people, MCP clients and agents. MIT licensed, self-hosted, your data stays in your own database.

[![Go Reference](https://pkg.go.dev/badge/github.com/glincker/theauth-go/v2.svg)](https://pkg.go.dev/github.com/glincker/theauth-go/v2)
[![CI](https://github.com/glincker/theauth-go/actions/workflows/ci.yml/badge.svg)](https://github.com/glincker/theauth-go/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/glincker/theauth-go?label=release)](https://github.com/glincker/theauth-go/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)

## Quickstart

A server with sign-up, sign-in, magic links, sessions and one protected route, stored in one SQLite file. Install with `go get github.com/glincker/theauth-go/v2` and `go get github.com/glincker/theauth-go/storage/sqlite` (the SQLite module needs Go 1.26, the root module Go 1.25).

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

`a.Handler()` is a plain `http.Handler`, so no `http.StripPrefix` is needed. With chi, call `a.Mount(r)` instead. More setups are in [examples](./examples) and the [docs](https://docs.theauth.dev/go).

## Why this exists

I needed a Go OAuth 2.1 authorization server for MCP clients and agents that runs inside my own process: RFC 9728 protected resource metadata, Client ID Metadata Documents (CIMD) and DPoP.
The same module also handles ordinary sign-in (passwords, magic links, passkeys, social login), so people and agents share one database.
It is young: the first commit is dated 2026-06-20. [When not to use it](./docs/WHEN-NOT-TO-USE.md) lists where fosite, zitadel/oidc, goth, authboss, Keycloak or Ory fit better.

## Status

Stable means SemVer applies. Beta means the API is covered by SemVer but I know of behavior gaps. Experimental means it may change in a minor release, or the [stability policy](https://docs.theauth.dev/go/reference/stability) does not cover it yet.

| Area | Status | Basis |
|---|---|---|
| Sign-in, sessions, social login, passkeys, TOTP | Stable | Root package, listed stable |
| Authorization server core: code with PKCE, refresh, client credentials, token exchange, discovery, dynamic registration | Stable | v2.0 commitment in the policy |
| MCP resource server (`mcpresource`) and RFC 9728 metadata | Stable | Listed stable package |
| DPoP, CIMD, PAR, JAR, CIBA, RAR, ID-JAG | Experimental | Not in the policy; CIMD options listed experimental |
| Agent identity and delegation | Experimental | Listed experimental |
| SAML SSO, SCIM, organizations, RBAC | Beta | API listed stable; no published IdP interop matrix |
| Memory storage, audit sinks | Stable | Listed stable |
| Postgres and MySQL storage | Beta | [Roadmap](./docs/ROADMAP.md): shared contract suite still fails on constraint edge cases |
| SQLite storage, `clientauth`, `policy`, Gin, Echo and Fiber adapters | Experimental | First three listed experimental; adapters not in the policy |

Levelrail, another product I build, imports it (pinned at v2.12.0). I have no independent audit or OpenID certification to point to. Other facts you can check yourself are in [docs/PROOF.md](./docs/PROOF.md).

## AI assistance

Parts of this code were written with AI assistance. I review it, and it is covered by tests (361 test files, count it with the commands in PROOF.md) and the [threat model](./docs/THREAT-MODEL.md). Codecov reported about 46 percent line coverage on 2026-10-31, so treat the tests as a floor. Report vulnerabilities privately through the [security policy](.github/SECURITY.md).

## Docs

[Install and verify releases](./docs/INSTALL.md) | [Features](./docs/FEATURES.md) | [Agent quickstart](./docs/AGENT-QUICKSTART.md) | [Storage](./docs/STORAGE.md) | [FAQ and migrating](./docs/FAQ.md) | [Examples](./docs/EXAMPLES.md) | [Changelog](CHANGELOG.md) | [About](./docs/ABOUT.md) | [Discussions](https://github.com/glincker/theauth-go/discussions)
