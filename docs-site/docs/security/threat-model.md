# Threat Model

This page summarizes the security design decisions in theauth-go and the threats
it is built to resist. It also documents what is explicitly out of scope.

!!! note "Full STRIDE analysis"
    A detailed STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure,
    Denial of Service, Elevation of Privilege) threat catalog is maintained in
    [`docs/THREAT-MODEL.md`](https://github.com/glincker/theauth-go/blob/main/docs/THREAT-MODEL.md)
    in the repository. The page you are reading is the operational quick-reference
    summary. Refer to the full document for per-subsystem threat tables and
    mitigating control details.

## Trust boundaries

```
Internet            ->   Reverse proxy (operator-managed)
                              |
                    ->   theauth-go HTTP handlers
                              |
                    ->   Storage (Postgres or memory, operator-managed)
```

theauth-go trusts the reverse proxy layer only when `Config.TrustedProxies` is explicitly set. By default, `X-Forwarded-For` is ignored and `r.RemoteAddr` is used for all rate-limiting and audit IP capture.

## Session tokens

- Raw session tokens are opaque (cryptographically random, `crypto/rand`).
- Only a SHA-256 hash is stored in the database. A full database dump does not yield usable session tokens.
- Cookies are set with `HttpOnly`, `Secure` (when `Config.SecureCookie` is true), and `SameSite=Lax`.
- Revocation is a single `UPDATE` that marks the session hash as invalid. The raw token in the cookie becomes useless immediately.

## Password handling

- Argon2id with OWASP 2026 recommended parameters.
- Minimum 12-character enforcement at sign-up.
- Anti-enumeration: unknown-email and empty-password branches pay the full Argon2id verify cost against a dummy hash synthesized once at `New` time. Timing side-channel is closed.
- Password reset tokens are single-use and short-lived (`PasswordResetTTL`, default 1 hour). Consuming a reset token revokes all sessions for the user.

## Rate limiting

- Per-IP and per-email rate limits on every credential endpoint.
- Rate limit buckets use `r.RemoteAddr` by default; `X-Forwarded-For` is only consulted when the proxy is in `Config.TrustedProxies`.
- POST `/oauth/register` has a separate per-IP rate limit: 1 req/min in anonymous mode, 5 req/min in bearer-gated mode.

## OAuth 2.1 AS

- PKCE S256 is mandatory. Requests without `code_challenge` are rejected.
- Audience binding (RFC 8707) is mandatory. Tokens are bound to a specific resource URI at mint time and verified at introspection.
- Refresh token family revocation: if a used (rotated) refresh token is presented again, the entire family is invalidated (RFC 9700).
- DCR bearer tokens are compared with `crypto/subtle.ConstantTimeCompare` against pre-hashed SHA-256 digests. Timing oracle on token presence is closed.
- Signing keys are AES-256-GCM encrypted at rest (requires `Config.EncryptionKey`).

## Agent and delegation

- Agent status transitions are audited. Suspended and revoked agents fail authentication immediately after the `clientauthcache` TTL (default 5 minutes) expires. The cache is busted synchronously on `SuspendAgent` and `RevokeAgent` (introduced in v2.1.0 PR #33).
- Delegation grants verify `body.userId` is a member of the admin's organization before creation (cross-org grant attack closed, audit H3 2026-06-20).
- Actor chain depth is capped at 3 at both the mint path and the config validation path (`ErrAgentChainDepthTooHigh`).

## WebAuthn / passkeys

- Sign-count replay protection: a new sign count must be strictly greater than the stored value. Clone-attempt returns `ErrReplayDetected`.
- Challenge storage is ephemeral and GC'd after `ChallengeTTL`.

## TOTP

- TOTP secrets are AES-256-GCM encrypted at rest.
- Recovery codes are SHA-256 hashed.
- 10 single-use recovery codes per user.

## SAML

- Only signed assertions are accepted (`ErrSAMLUnsignedAssertion` on unsigned).
- AuthnRequest replay tracking with a configurable TTL.

## SCIM

- Bearer tokens are SHA-256 hashed. Full token never stored.
- Per-organization isolation enforced at every CRUD endpoint.

## Out of scope

The following are explicitly not covered by theauth-go:

- **TLS termination.** Run a TLS-terminating reverse proxy (nginx, Caddy, AWS ALB) in front.
- **DDoS and volumetric flood protection.** Use a WAF or CDN-level rate limiter for sustained volumetric attacks.
- **Physical security of the host running Postgres.**
- **Audit tamper-evidence.** The `audit_events` table is append-only but not Merkle-chained in v2.3. Tamper-evidence via signed audit chains is on the v2.x roadmap.
- **ABAC and hierarchical roles.** RBAC is a closed permission catalog with flat roles. Time-bound and attribute-based access control are deferred.
- **Hardware-attested agent credentials.** `AgentCredentialKindJWK` and `AgentCredentialKindX509` paths exist but return `ErrNotImplemented`. TPM-backed signing is a planned future feature.

## Reporting security issues

See [SECURITY.md](https://github.com/glincker/theauth-go/blob/main/SECURITY.md). Report security vulnerabilities to `security@glincker.com`. Do not open public issues for security findings.
