# theauth-go storage/sqlite

Pure Go (`modernc.org/sqlite`, no cgo) storage adapter for [theauth-go](https://github.com/glincker/theauth-go). It runs on a `*sql.DB` you own.

```sh
go get github.com/glincker/theauth-go/storage/sqlite
```

## Capabilities

| Capability | Migration |
|---|---|
| Users, sessions, magic links, passwords, OAuth accounts, passkeys, TOTP, audit | 0001 to 0005, 0008 |
| Session management and session links | 0006 |
| Scoped API tokens, device codes | 0007, 0009, 0018 |
| Account lifecycle (disable, delete, must change password), trusted devices | 0010 |
| Device identity (join tokens, enrolled devices) | 0011 |
| Shared signals | 0012 |
| Organizations and per-session active organization | 0013 |
| SAML connections and identities | 0014 (needs 0013) |
| SCIM tokens, groups, group members | 0015 (needs 0013) |
| RBAC permissions, roles, grants | 0016 (needs 0013) |
| Audit accountability fields and tamper-evident hash chain | 0017 |
| Agent tool approvals (single use) | 0019 |
| OAuth 2.1 authorization server: clients, authorization codes, refresh tokens, revoked jti denylist, JWKS keys | 0020 to 0024 |
| Pushed authorization requests, opaque access tokens, device authorization grant, registration tokens | 0025 to 0028 |
| Cascade triggers for OAuth clients | 0029 |
| Agents and agent credentials | 0030 |
| Delegation grants | 0031 |
| jwt-bearer `jti` cache | 0032 |
| CIBA backchannel requests | 0033 |
| Session authentication methods (`amr`, `auth_time`) | 0034 |

`Migrate` applies every pending file. If you own the schema, use `Migrations` or `RenderMigrations` and apply the files you need in order. The OAuth 2.1 authorization server (0020 to 0029) runs on this store alone, together with agents and delegation grants (0030, 0031), the jwt-bearer cache (0032) and CIBA (0033). See [docs/mcp-oauth-sqlite.md](../../docs/mcp-oauth-sqlite.md) for a guide, and [docs/storage-capabilities.md](../../docs/storage-capabilities.md) for how this store compares with the others.

## Running on an older schema

A database that has not run every migration keeps working for the features it already had.

- **Sessions without 0034.** Sessions are read and written without an authentication record (`AuthMethods` is nil and `AuthTime` is zero), and `AppendSessionAuthMethods` returns `ErrStorageMissingCapability`. Tokens fall back to `amr: ["pwd"]`. Apply 0034 and create a new `Store` to turn the record on.
- **Audit without 0017.** Events are written and read in the old shape and are not chained. Rows written before the migration stay unchained and are never rewritten.
- **OAuth server tables (0020 to 0029).** Apply them before you enable `Config.AuthorizationServer`.

## Enable SAML and SCIM

```go
db, _ := sql.Open("sqlite", "file:app.db?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_txlock=immediate")
_ = sqlitestore.Migrate(ctx, db)
store, _ := sqlitestore.New(db)

auth, err := theauth.New(theauth.Config{
	Storage:       store,
	BaseURL:       "https://app.example.com",
	Organizations: &theauth.OrganizationsConfig{},
	SAML:          &theauth.SAMLConfig{SPCertificatePEM: certPEM, SPPrivateKeyPEM: keyPEM},
	SCIM:          &theauth.SCIMConfig{RequireHTTPS: true},
})
```

## Notes

- Foreign keys must be on; `New` refuses a database with them off. Use `busy_timeout`, WAL mode and `_txlock=immediate` on a shared file. A single process per database file is the supported shape; use Postgres or MySQL for several replicas.
- OAuth signing keys are sealed with `Config.EncryptionKey` (32 bytes). Back up the key with the database file.
- Organization slugs are lowercased and unique. Deleting an organization cascades to members, SAML connections and identities, SCIM tokens, groups and roles, and clears the active organization of sessions that pointed at it.
- SCIM tokens are stored as sha256 hashes. SAML connections hold the IdP certificate and URLs only.
- `SweepExpired` removes expired sessions, magic links, reset tokens, trusted devices, session links, device codes and join tokens. Call it from a ticker.
- Deactivating a user through SCIM revokes their sessions (all of them when it was their last organization, otherwise those active in that organization) and removes the membership.
