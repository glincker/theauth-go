// Package tokenvault stores third party OAuth credentials (access and refresh
// tokens) encrypted at rest and lets an agent obtain a short lived access
// token for a connected provider on behalf of a user, without the agent ever
// holding the refresh token.
//
// Tokens are sealed with AES-256-GCM using a caller supplied KeyRing. Every
// sealed blob carries the id of the key that produced it, so keys can be
// rotated and old blobs re-sealed with Vault.Rewrap. The ciphertext is bound
// to its user, provider and field, so a row copied to another user does not
// decrypt.
//
// Persistence goes through the optional theauth.TokenVaultStorage capability.
// Only the in-memory store implements it today; there is no SQL backend yet.
//
// The package never logs a token and never puts one in an error, an audit
// event or a String method.
package tokenvault
