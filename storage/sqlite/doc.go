// Package sqlite implements theauth storage capabilities on top of a caller-owned *sql.DB using the pure Go modernc.org/sqlite driver.
//
// It covers CoreStorage (users, sessions, magic links, passwords) plus OAuthAccount, WebAuthn, TOTP, Audit, session management, links, API tokens, device codes, TOTP replay, user count, passkey rename, and recovery codes. Organizations, SAML, SCIM and RBAC are not implemented.
//
// The caller opens the database and owns its pragmas. Foreign keys must be on for every connection, and busy_timeout plus WAL mode are strongly advised for shared databases. A complete DSN: file:app.db?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_txlock=immediate
//
// Schema ownership is either the host's, via Migrations and RenderMigrations, or this package's, via Migrate.
package sqlite
