# Authorization server threat model

Scope: the OAuth 2.1 / MCP authorization server (`AuthorizationServerConfig`), its storage, and the `mcpresource` validator. This page records what each control defends against and where the limits are.

## Credentials at rest

| Secret | Stored as | Notes |
| --- | --- | --- |
| Authorization code | SHA-256 hex of the code | Hashed in every backend (memory, postgres, mysql) by the service before it reaches storage. A database read yields nothing redeemable. Migration 0019 drops any plaintext codes still in flight (60 second TTL). |
| Refresh token | SHA-256 of the token | Rotated on every use. |
| Client secret | Argon2id PHC string | Hashes below the current cost are upgraded on login. |
| Signing keys | AES-GCM sealed | Key from `Config.EncryptionKey`. |

Earlier revisions of this document said codes were hashed; before 0019 they were not.

## Authorization code replay

A code is single use. If an already redeemed code is presented again, the server revokes every refresh token family first issued from it (RFC 6749 section 4.1.2) and, when the access token denylist is on, the access tokens too. Storage adapters opt in by implementing `RevokeRefreshTokensByAuthCode`; the in-tree adapters do. Without it, replay is still rejected but earlier tokens survive.

## Sender-constrained tokens (DPoP, RFC 9449)

- A refresh token minted for a DPoP-bound grant stores the key thumbprint (`dpop_jkt`). Every refresh must carry a proof from the same key, and the new tokens stay bound. A missing or foreign proof is `invalid_dpop_proof` and does not consume the token. There is no downgrade to Bearer.
- Token exchange (RFC 8693) with a DPoP-bound subject token needs a proof from the bound key and the issued token inherits `cnf.jkt` and `token_type=DPoP`.
- The expected `htu` is built from the configured issuer. `X-Forwarded-Proto` and `X-Forwarded-Host` are not consulted, so a proof minted for another origin does not pass.
- Custom storage adapters must persist `RefreshToken.DPoPJKT` and `AuthCodeHash`. An adapter that drops them silently loses refresh binding.

## Revocation

- `/oauth/revoke` only acts on tokens issued to the authenticated client (RFC 7009 section 2.1). A mismatch answers 200 and does nothing, so one client cannot probe or kill another's tokens.
- Access tokens are stateless JWTs. Setting `AuthorizationServerConfig.AccessTokenRevocation` turns on a store-backed `jti` denylist whose entries live until the token's own `exp`. Revocation, code replay and token exchange consult it, and introspection reports revoked tokens inactive. Off by default.
- Limit: resource servers that verify JWTs locally never see the denylist. They must introspect, or rely on the short access token TTL.

## Client registration

- Client ID Metadata Documents are the preferred path (MCP authorization spec 2026-07-28). Fetches are SSRF-guarded: non-public addresses refused at dial time, no redirects, no proxy, 5 KiB body cap by default, concurrent fetches of one URL collapsed into one, failures cached briefly (`NegativeCacheTTL`). The `client_id` URL must have a path and no userinfo, fragment or dot segments.
- Dynamic Client Registration is deprecated by that spec and kept for compatibility. `registration_endpoint` is advertised only when `RegistrationTokens` or `AllowAnonymousRegistration` is set.
- Redirect URIs (DCR and CIMD) must be `https`, `http` on a loopback host with any port (RFC 8252 section 7.3), or a reverse-DNS private-use scheme. `javascript:`, `data:`, `file:` and dotless custom schemes are refused.
- Authorization responses carry `iss` (RFC 9207) and metadata sets `authorization_response_iss_parameter_supported`.

## Error disclosure

Server faults on OAuth endpoints return a generic `server_error` description. Detail goes to the log only.

## Resource server and sinks

- `mcpresource` requires `typ: at+jwt` (RFC 9068) by default. `WithAllowMissingTyp()` tolerates an absent typ for servers that omit it; a wrong typ is always rejected. The same rule applies inside the AS (`jwt.Verify`; `jwt.VerifyOpts` has the tolerant mode).
- The JWKS cache serves stale keys during an outage only up to `WithJWKSMaxStale` (default 1 hour), then fails closed.
- Webhook audit sink signatures cover `"<unix-seconds>." + body`, with the timestamp in `X-CloudEvents-Timestamp`. `webhook.Verify` checks the MAC in constant time and rejects timestamps outside a window (default 5 minutes), which bounds replay of a captured delivery.

## Out of scope here

Rate limiting of AS endpoints and client IP derivation are covered by their own controls (`TrustedProxies`, per-IP limits) and are not changed by this hardening pass.
