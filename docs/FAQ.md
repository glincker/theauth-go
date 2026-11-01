# FAQ, migrating and library versus hosted

## Library or hosted service

theauth-go is a library you embed and run yourself, so you own the database and the operations. It does not include a hosted login UI or a managed service. If you need either, it is not the right shape for you. The TypeScript library at [glincker/theauth](https://github.com/glincker/theauth) covers Node, Bun, Deno and Workers backends.

## Migrating

- From Auth0: [Migrate from Auth0](https://docs.theauth.dev/go/guides/migrate-from-auth0)
- From Cognito: [Migrate from Cognito](https://docs.theauth.dev/go/guides/migrate-from-cognito)
- From Keycloak: [Migrate from Keycloak](./MIGRATING-FROM-KEYCLOAK.md)
- From hand-rolled sessions: [Migrate from hand-rolled sessions](https://docs.theauth.dev/go/guides/migrate-from-hand-rolled-sessions)
- From the v1 module path: [Migrating to /v2](https://docs.theauth.dev/go/migrations/to-v2-module-path)

## FAQ

**Does theauth-go work without Postgres?**
Yes. Use `storage/sqlite` for a single static binary with one database file, `storage/memory` for tests, or MySQL. SQLite supports organizations, SAML, SCIM and RBAC, and runs the OAuth 2.1 authorization server, agents and CIBA (migrations 0020 to 0034); see docs/storage-capabilities.md.

**How do I add passkeys to a Go app?**
Set `Config.WebAuthn` and use a storage backend that implements `WebAuthnStorage` (all four built in backends do). Register and login routes are then mounted under your auth handler. See the [passkeys guide](https://docs.theauth.dev/go/guides/webauthn-passkeys) and [`examples/webauthn-passkey`](../examples/webauthn-passkey).

**Does it support MCP authorization?**
Yes. The library can act as the OAuth 2.1 authorization server and publishes protected resource metadata. The separate zero dependency `mcpresource` module validates tokens inside an MCP resource server. See [MCP authorization](https://docs.theauth.dev/go/concepts/mcp-authorization) and [`examples/mcp-server`](../examples/mcp-server).

**How do I migrate from Auth0, Cognito or Keycloak?**
Follow [Migrate from Auth0](https://docs.theauth.dev/go/guides/migrate-from-auth0), [Migrate from Cognito](https://docs.theauth.dev/go/guides/migrate-from-cognito) or [Migrate from Keycloak](https://github.com/glincker/theauth-go/blob/main/docs/MIGRATING-FROM-KEYCLOAK.md). Password hashes carry over and upgrade to Argon2id at each user's first login. Coming from hand-rolled sessions: [Migrate from hand-rolled sessions](https://docs.theauth.dev/go/guides/migrate-from-hand-rolled-sessions).

**Which Go versions are supported?**
The root module and `storage/sqlite` both need Go 1.26.

**Is it a hosted service?**
No. It is a library you run inside your own process, under the MIT license.
