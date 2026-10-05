// Package sqlite implements theauth storage capabilities on top of a
// caller-owned *sql.DB using the pure Go modernc.org/sqlite driver.
//
// It covers CoreStorage (users, sessions, magic links, passwords) plus the
// OAuthAccount, WebAuthn, TOTP and Audit capabilities. Organizations, SAML,
// SCIM and RBAC are not implemented, so a Config that enables them fails
// with theauth.ErrStorageMissingCapability.
//
// The caller opens the database and owns its pragmas. Foreign keys must be on
// for every connection, and busy_timeout plus WAL mode are strongly advised
// for any database shared with other writers. A DSN that does all three:
//
//	file:app.db?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_txlock=immediate
//
// Schema ownership is either the host's, via Migrations and RenderMigrations,
// or this package's, via Migrate and its own version table.
package sqlite
