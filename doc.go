// Package theauth provides session-based authentication for Go applications.
//
// TheAuth ships magic-link email auth, opaque session tokens with revocation,
// and chi-friendly middleware. Storage backends include in-memory and Postgres
// (pgx + sqlc). OAuth providers, TOTP, WebAuthn, and MCP OAuth 2.1 land in
// future versions — see the README roadmap.
package theauth
