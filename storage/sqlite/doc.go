// Package sqlite implements theauth storage capabilities on top of a caller-owned *sql.DB using the pure Go modernc.org/sqlite driver.
//
// It covers CoreStorage (users, sessions, magic links, passwords) plus OAuthAccount, WebAuthn, TOTP, Audit, session management, links, API tokens, device codes, TOTP replay, user count, passkey rename, and recovery codes. It also implements Organization, SAML, SCIM and RBAC storage (migrations 0013 to 0016), account state, account delete and trusted devices (migration 0010), device identity (migration 0011), shared signals (migration 0012), the audit hash chain (migration 0017) and single use tool approvals (migration 0019).
//
// Migrations 0020 to 0034 add the OAuth 2.1 authorization server and what runs on it: clients, authorization codes, refresh tokens, the access token denylist and JWKS keys (0020 to 0024), pushed authorization requests, opaque access tokens, the device authorization grant and registration tokens (0025 to 0028), cascade triggers (0029), agents (0030), delegation grants (0031), the jwt-bearer jti cache (0032), CIBA backchannel requests (0033) and session authentication methods (0034). A database that has not run 0034 keeps working: sessions have no authentication record and recording one returns ErrStorageMissingCapability.
//
// The caller opens the database and owns its pragmas. Foreign keys must be on for every connection, and busy_timeout plus WAL mode are strongly advised for shared databases. A complete DSN: file:app.db?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_txlock=immediate
//
// Schema ownership is either the host's, via Migrations and RenderMigrations, or this package's, via Migrate.
package sqlite
