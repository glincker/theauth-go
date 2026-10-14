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
| Scoped API tokens, device grant | 0007, 0009 |
| Account lifecycle (disable, delete, must change password), trusted devices | 0010 |
| Device identity | 0011 |
| Shared signals | 0012 |
| Organizations and per-session active organization | 0013 |
| SAML connections and identities | 0014 (needs 0013) |
| SCIM tokens, groups, group members | 0015 (needs 0013) |
| RBAC permissions, roles, grants | 0016 (needs 0013) |

`Migrate` applies every pending file. If you own the schema, use `Migrations` or `RenderMigrations` and apply the files you need in order. The OAuth 2.1 authorization server is not implemented.

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

- Foreign keys must be on; `New` refuses a database with them off.
- Organization slugs are lowercased and unique. Deleting an organization cascades to members, SAML connections and identities, SCIM tokens, groups and roles, and clears the active organization of sessions that pointed at it.
- SCIM tokens are stored as sha256 hashes. SAML connections hold the IdP certificate and URLs only.
- `SweepExpired` removes expired sessions, magic links, reset tokens, trusted devices, session links, device codes and join tokens. Call it from a ticker.
- Deactivating a user through SCIM removes the organization membership. Sessions are not revoked by the core library; call `RevokeUserSessions` or `DisableUser` when you need that.
