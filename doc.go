// Package theauth provides OAuth 2.1 and MCP authorization for Go
// applications, alongside magic-link, email/password, WebAuthn passkey,
// TOTP, SAML, and SCIM authentication.
//
// TheAuth ships an OAuth 2.1 authorization server (PKCE-mandatory
// authorization code, client_credentials, refresh token rotation, RFC 8693
// token exchange, CIBA, PAR, JAR, DPoP-bound tokens), RFC 9728 MCP resource
// server metadata, agent identities with revocable delegation chains,
// organization-scoped RBAC, and an async audit log. Storage backends
// include in-memory, Postgres (pgx), and MySQL. See docs/AGENTS.md or
// https://theauth.dev for the full feature list and quick start.
package theauth
