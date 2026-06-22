# Threat Model

**Scope:** theauth-go library, as deployed by an operator in a Go HTTP application.
**Method:** STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege).
**Last reviewed:** 2026-06-22

---

## Table of Contents

1. [Trust Boundaries](#trust-boundaries)
2. [Components in Scope](#components-in-scope)
3. [Out of Scope](#out-of-scope)
4. [Authorization Server (AS)](#authorization-server-as)
5. [Resource Server / mcpresource](#resource-server--mcpresource)
6. [Storage Backend](#storage-backend)
7. [Authentication Flows](#authentication-flows)
8. [Grant Types](#grant-types)
9. [Audit Subsystem](#audit-subsystem)
10. [Session Subsystem](#session-subsystem)
11. [Agent Identity Flow](#agent-identity-flow)
12. [Delegation Chains](#delegation-chains)
13. [Threat Catalog](#threat-catalog)

---

## Trust Boundaries

| Boundary | What Crosses It | Direction |
|---|---|---|
| HTTP network | OAuth/OIDC protocol messages (authorize, token, introspect, JWKS) | Inbound from clients/browsers |
| HTTP network | Provider OAuth callbacks (GitHub, Google, Apple, etc.) | Inbound from IdP |
| Process/DB | SQL queries and responses | Bidirectional |
| Process/SIEM | Audit events forwarded to sinks (OTLP, Splunk, webhook) | Outbound |
| Process/email | Magic link and password reset emails | Outbound |
| HTTPS/IdP | CIMD metadata document fetches | Outbound, HTTPS only |
| Process memory | Signing keys (Ed25519 private keys) | In-process only |

The library does **not** control what crosses the operator's TLS terminator, the operator's secret store, or the operator's hosting environment. Those are explicitly out of scope.

---

## Components in Scope

- **Authorization Server (AS):** issues JWTs (authorization_code, refresh_token, client_credentials, token_exchange grants). Lives in `internal/as/`.
- **Resource Server / mcpresource:** validates inbound JWTs at protected API endpoints. Lives in `mcpresource/`.
- **Storage backend:** memory store (`storage/memory/`) and Postgres store (`storage/postgres/`). Pluggable via the `Storage` interface in `storage.go`.
- **Authentication flows:** password, OAuth social login, magic link, WebAuthn, TOTP, SAML, SCIM.
- **Audit subsystem:** event emission, redaction, sinks. Lives in `internal/audit/`, `audit/`.
- **Session subsystem:** session minting, lookup, expiry, revocation. Lives in `internal/session/`.
- **Agent identity flow:** machine credential issuance and revocation. Lives in `internal/agent/`.
- **Delegation chains:** scoped delegation grants. Lives in `internal/delegation/`.
- **CIMD (Client Identity Metadata Document):** fetches and caches machine-client metadata. Lives in `internal/cimd/`.
- **RBAC:** role and permission enforcement. Lives in `internal/rbac/`.

---

## Out of Scope

The following are explicitly **not** mitigated by this library. They are the deploying operator's responsibility.

- **TLS termination and certificate management.** The library emits a `slog.Warn` when `SecureCookie=false` (see `theauth.go:41-45`) but cannot enforce TLS on the transport layer itself.
- **Secret management at rest.** Encryption keys (`AuditConfig.EncryptionKey`, TOTP key, etc.) must be supplied by the operator; the library does not manage a secret store.
- **Container/VM/Kubernetes pod isolation.** Network policies, pod security admission, and kernel security modules are outside library scope.
- **Operator's authentication device security.** TOTP app compromise, WebAuthn key theft, or phone compromise for CIBA-style flows are not addressable at the library layer.
- **DDoS at the network layer.** The library provides application-layer rate limits (`RateLimitByIP`, `RateLimitByEmail` in `middleware_ratelimit.go:171-229`) but not TCP/UDP-layer flood protection.
- **Side channels in Go runtime or `crypto/subtle`.** The library uses `crypto/subtle` for all sensitive comparisons but cannot guarantee the Go runtime's memory allocator or garbage collector do not introduce timing channels.

---

## Authorization Server (AS)

### Trust Boundaries

- Receives `client_id`, `client_secret`, `code_verifier`, and `DPoP` header values over HTTP.
- Reads client rows and authorization code rows from storage.
- Holds Ed25519 private keys in process memory (`internal/as/service.go:69`).
- Writes access tokens and refresh tokens to storage.

### STRIDE Analysis

**Spoofing**

| Threat | Mitigation | Residual Risk |
|---|---|---|
| Client impersonation via stolen `client_secret` | `client_secret_hash` stored as Argon2id PHC; verified with `subtle.ConstantTimeCompare` (`internal/clientauthcache/cache.go:118`). Cache invalidated on suspend/revoke (`internal/clientauthcache/cache.go:165`). | Operator must protect secret in transit (HTTPS) and at rest (secret store). |
| Authorization code interception (open-redirect) | `redirect_uri` must match the registered URI exactly (`internal/as/token.go:92-93`). Registration enforces HTTPS or localhost-only (`internal/as/dcr.go:206-228`). | Operator must not register wildcard redirect URIs. |
| Authorization code injection (inline param tampering) | PKCE S256 enforced on every code exchange (`internal/as/token.go:99-103`). PAR (Pushed Authorization Request) is not yet implemented; see residual risk. | Without PAR, `state` can carry injected parameters on the redirect leg. Mitigated by `RequireState=true` (`internal/as/config.go:102-107`) to force callers to include a non-empty state. Full mitigation requires PAR (planned). |
| Token replay after bearer theft | DPoP (RFC 9449) binding embeds `cnf.jkt` in the access token (`internal/as/token.go:234-245`), tying the token to the proof key. Resource servers must require a matching DPoP proof on each request. | Operator must enable `DPoP` in AS config and configure resource servers to require it. Bearer tokens remain exchangeable without DPoP when the operator has not enabled it. |

**Tampering**

| Threat | Mitigation | Residual Risk |
|---|---|---|
| JWT claim forgery | Tokens are Ed25519-signed; signature is verified by the resource server against the JWKS endpoint. | Signing keys in process memory. Compromise of the process compromises all issued tokens until key rotation. |
| PKCE downgrade (plain method) | S256 is the only accepted method; `plain` is not implemented (`crypto/pkce.go`). | None within the library. |
| JWKS rotation race | `AtomicRotateJWKS` issues all state transitions in a single database transaction when the storage adapter implements `JWKSAtomicRotator` (`internal/as/jwks.go:295-338`). Previous key is retained so tokens signed by it remain valid during the overlap window. | Operators using a custom storage adapter that does not implement `JWKSAtomicRotator` fall back to a non-atomic rotation path (`internal/as/jwks.go:339`). They should implement the interface. |

**Repudiation**

| Threat | Mitigation | Residual Risk |
|---|---|---|
| Deny issuing a token | Every token issuance emits an audit event (`internal/as/token.go` audit calls). | Operator must stream audit events to an external SIEM to maintain tamper-evident logs. |

**Information Disclosure**

| Threat | Mitigation | Residual Risk |
|---|---|---|
| Client secret exposure | Never stored in plaintext; stored as Argon2id PHC hash. | Operator must not log request bodies containing `client_secret`. |
| Authorization code in server logs | The code is stored as a hash; the raw value is returned to the client only over the redirect response. | Operator must not log full redirect URLs. |

**Denial of Service**

| Threat | Mitigation | Residual Risk |
|---|---|---|
| Credential stuffing on token endpoint | `RateLimitByIP` and `RateLimitByEmail` middlewares (`middleware_ratelimit.go:171-229`). | Rate limit budgets are configurable; operator must tune to production traffic patterns. |
| Argon2 CPU exhaustion | Password verification pays the full Argon2id cost even on user-not-found to prevent timing-based user enumeration (`internal/password/service.go:240`). | At default `m=64MiB, t=3, p=4` this is intentionally expensive; operators must size compute accordingly. |

**Elevation of Privilege**

| Threat | Mitigation | Residual Risk |
|---|---|---|
| CSRF on /authorize | `state` parameter required when `RequireState=true` (`internal/as/config.go:107`). | Operator must set `RequireState=true` in production. Default is `false` for backward compatibility. |
| Open redirect via malformed `redirect_uri` | Fragment, non-HTTPS, and non-localhost HTTP URIs are rejected at registration time (`internal/as/dcr.go:206-228`). | Custom native-app URI schemes (e.g., `myapp://`) are permitted as registered; operator must audit registered URIs. |

---

## Resource Server / mcpresource

### Trust Boundaries

- Receives HTTP requests with `Authorization: Bearer <token>` or `Authorization: DPoP <token>` plus optional `DPoP:` proof header.
- Fetches public keys from the JWKS endpoint (operator-configured URL, cached in process).
- No storage writes.

### STRIDE Analysis

**Spoofing**

| Threat | Mitigation | Residual Risk |
|---|---|---|
| Token replay across resources | `cnf.jkt` claim in DPoP-bound tokens ties the token to the proof key; `aud` claim restricts to the intended resource server. | Operator must configure audience validation (`mcpresource/validator.go`) and enforce DPoP when required. |
| Bearer token presented as DPoP token | Token type `DPoP` vs `Bearer` is checked; mismatched type is rejected (`mcpresource/dpop.go`). | None within the library. |

**Tampering**

| Threat | Mitigation | Residual Risk |
|---|---|---|
| JWT claim alteration | Ed25519 signature covers the full JWT header + payload; any modification invalidates it. | None. |

**Information Disclosure**

| Threat | Mitigation | Residual Risk |
|---|---|---|
| Key material in JWKS cache | Only public keys are cached. Private keys never leave the AS process. | Operator must serve the JWKS endpoint over HTTPS. |

**Denial of Service**

| Threat | Mitigation | Residual Risk |
|---|---|---|
| JWKS endpoint unavailability | Keys are cached in process; a short outage does not immediately block validation. | Operator must size JWKS cache TTL against acceptable key-stale window. |

---

## Storage Backend

### Trust Boundaries

- Library code speaks to storage via the `Storage` interface (defined in `storage.go`).
- Postgres store uses parameterized queries (sqlc-generated); no string concatenation in SQL.
- Memory store is in-process only; no network trust boundary.

### STRIDE Analysis

**Tampering**

| Threat | Mitigation | Residual Risk |
|---|---|---|
| Direct database writes bypassing application logic | The `Storage` interface is the only sanctioned path; the library does not grant the application DB user DDL rights. | Operator must restrict the DB user to DML only on theauth tables. |

**Information Disclosure**

| Threat | Mitigation | Residual Risk |
|---|---|---|
| SQL injection | All queries use sqlc-generated parameterized statements. | Operator must not hand-write raw SQL against the same connection pool. |
| Password hash leak from DB dump | Passwords stored as Argon2id PHC strings only; no plaintext. | A database dump exposes hashes; offline cracking is bounded by Argon2id cost. |
| TOTP secret leak from DB dump | TOTP secrets encrypted with AES-256-GCM before storage (`internal/totp/service.go:225`). | Leak of both the DB dump and the encryption key compromises TOTP secrets. Operator must store the encryption key separately. |

**Denial of Service**

| Threat | Mitigation | Residual Risk |
|---|---|---|
| Connection pool exhaustion | Not addressed within the library; the library uses whatever `*sql.DB` the operator passes. | Operator must configure `MaxOpenConns` and `MaxIdleConns`. |

---

## Authentication Flows

### Password

**Trust Boundaries:** Receives plaintext password over HTTP (must be HTTPS at operator's transport layer). Reads password hash from storage.

| Threat | Mitigation | File Reference |
|---|---|---|
| Password enumeration via timing | Argon2id cost paid even for non-existent users (`internal/password/service.go:240`). | `internal/password/service.go:240` |
| Weak hash algorithm | Argon2id with `m=64MiB, t=3, p=4` per OWASP 2026 baseline (`crypto/password.go:14,26-28`). | `crypto/password.go:26-28` |
| Work-factor downgrade | Hash params are embedded in the PHC string; `VerifyPassword` reads them back (`crypto/password.go:62-84`). A stored hash with weaker params can still be verified; the operator may re-hash on next login. | Operator must define a minimum work-factor upgrade policy. |

**Residual risk:** Operator must enforce HTTPS to prevent plaintext password capture.

### OAuth Social Login

**Trust Boundaries:** Operator's app redirects user to provider; provider redirects back with `code` + `state`. The `state` is a crypto/rand token stored in an HttpOnly cookie for CSRF protection.

| Threat | Mitigation | File Reference |
|---|---|---|
| Provider CSRF via forged state | `state` is `crypto.NewToken()` (32 bytes, base64url) stored in HttpOnly cookie; callback verifies cookie value matches query param (`internal/oauth/handlers/handlers.go:73-108`). | `internal/oauth/handlers/handlers.go:101-109` |
| Apple .p8 key leak | Documented operator responsibility in `provider/apple/apple.go:8-18`. Library does not store the key; operator must supply it. | `provider/apple/apple.go:8-18` |
| Provider token replay | `oauthStateTTL` (10 min) expires the state cookie (`internal/oauth/handlers/handlers.go:25-26`). | `internal/oauth/handlers/handlers.go:24-26` |

### Magic Link

**Trust Boundaries:** Token emailed to user; operator's email delivery path is outside library scope.

| Threat | Mitigation | File Reference |
|---|---|---|
| Token brute-force | Tokens are 32-byte crypto/rand values stored as SHA-256 hashes; brute-force infeasible. | `crypto/tokens.go`, `internal/magiclink/service.go:118` |
| Token reuse | `ConsumeMagicLink` is an atomic consume; a second use returns `ErrMagicLinkExpired` or `ErrMagicLinkAlreadyUsed`. | `internal/magiclink/service.go:113-126` |
| Token lifetime | Default TTL is 15 minutes (operator-configurable via `MagicLinkTTL`; `wiring.go:52-53`). | `wiring.go:52-53` |

### WebAuthn

**Trust Boundaries:** Browser generates a cryptographic assertion over the challenge; assertion verified against stored public key.

| Threat | Mitigation | File Reference |
|---|---|---|
| Credential replay (cloned authenticator) | Sign counter monotonic check: if `newCount <= stored.SignCount` the library returns `ErrReplayDetected` (`internal/webauthn/service.go:431-436`; sentinel defined at `internal/webauthn/service.go:108`). | `internal/webauthn/service.go:108,431-436` |
| Phishing (wrong origin) | WebAuthn RP ID and origin are enforced by the `go-webauthn/webauthn` library; challenge is per-registration/authentication. | Operator must configure `RPID` and `RPOrigins` correctly. |

### TOTP

**Trust Boundaries:** User supplies 6-digit code generated by an authenticator app.

| Threat | Mitigation | File Reference |
|---|---|---|
| TOTP secret at rest | Encrypted with AES-256-GCM before insertion (`internal/totp/service.go:225`). | `internal/totp/service.go:225` |
| Code replay within window | Standard TOTP: each code is valid for one 30-second window. Time skew tolerance is governed by the underlying library. | Operator must ensure server clock is NTP-synced. |

### SAML

**Trust Boundaries:** IdP posts a signed XML assertion to the library's SP assertion consumer service.

| Threat | Mitigation | File Reference |
|---|---|---|
| XML signature wrapping (XSW) | SAML assertions are processed via `crewjam/saml` (v0.5.1) and `russellhaering/goxmldsig` (v1.4.0), which validate that the XML signature covers the full assertion including the `<Issuer>` and `<Conditions>` elements. | `go.mod:7,14`; `internal/saml/service.go:41` |
| Unauthorized IdP | Each SAML connection stores the IdP certificate; assertions are only accepted when signed by the registered certificate. | Operator must use genuine IdP metadata when creating a SAML connection. |

### SCIM

**Trust Boundaries:** SCIM client presents a bearer token; library validates it against a stored hash.

| Threat | Mitigation | File Reference |
|---|---|---|
| Token reuse / stale token | `last_used_at` is updated asynchronously on each valid request (`internal/scim/service.go:117-138`). | `internal/scim/service.go:117-138` |
| Unauthenticated SCIM requests | `middleware_scim.go` gates all SCIM endpoints behind token validation. | `middleware_scim.go` |

---

## Grant Types

### Authorization Code + PKCE

| Threat | Mitigation | File Reference |
|---|---|---|
| PKCE downgrade | `plain` method not implemented; S256 enforced. `CodeChallenge()` computes `base64url(sha256(verifier))` (`crypto/pkce.go:33-37`). | `crypto/pkce.go:33-37` |
| Code interception | `subtle.ConstantTimeCompare` used when comparing computed challenge against stored challenge (`internal/as/token.go:99-103`). | `internal/as/token.go:99-103` |

### Refresh Token

| Threat | Mitigation | File Reference |
|---|---|---|
| Stolen refresh token reuse | Every use rotates the token; presenting an already-rotated token triggers family-wide revocation per RFC 9700 section 4.14 (`internal/as/token.go:122-176`; documented in `internal/as/config.go:45-47`). | `internal/as/token.go:122-176` |

### Client Credentials

| Threat | Mitigation | File Reference |
|---|---|---|
| Credential stuffing | `subtle.ConstantTimeCompare` on `client_secret` via the auth cache (`internal/clientauthcache/cache.go:118`). Rate limits apply at the network layer. | `internal/clientauthcache/cache.go:118` |

### Token Exchange (RFC 8693)

| Threat | Mitigation | File Reference |
|---|---|---|
| Scope escalation via exchange | Delegation scope is always narrowed to the intersection of requested, subject, and grant scopes (`internal/delegation/service.go:263-291`). | `internal/delegation/service.go:263-291` |
| Exchange using suspended/revoked agent token | Introspection path re-walks the chain on every exchange; suspended/revoked agent in the chain causes rejection (`internal/as/introspect.go:161-192`). | `internal/as/introspect.go:161-192` |

### DPoP-Bound Tokens (RFC 9449)

| Threat | Mitigation | File Reference |
|---|---|---|
| Bearer token replay | `cnf.jkt` thumbprint embedded in the token ties it to the specific key pair (`internal/as/token.go:201-245`). Resource server validates the inbound DPoP proof carries the same `jkt` (`mcpresource/dpop.go`). | `internal/as/token.go:234-245` |
| DPoP nonce replay | Nonce is HMAC-verified at each use; nonces are short-lived (`internal/dpop/nonce.go:71`). | `internal/dpop/nonce.go:71` |

### PAR (Pushed Authorization Request)

PAR is not yet implemented in the current codebase. Without PAR, authorization request parameters are passed as query string values on the redirect. An attacker who can intercept the redirect URL can observe but not forge them (PKCE protects the exchange). Full authorization code injection mitigation requires PAR. When PAR lands, the `request_uri` reference replaces the inline parameters.

**Residual risk (current):** Operators with strict injection requirements should combine `RequireState=true` with PKCE S256 (both currently available) until PAR is implemented.

---

## Audit Subsystem

### Trust Boundaries

- Events are emitted in-process; sink goroutines forward them out-of-process to OTLP, Splunk, or webhook endpoints.
- The webhook sink signs each request body with HMAC-SHA256 (`audit/sinks/webhook/webhook.go:4-5,131`).

### STRIDE Analysis

**Repudiation**

| Threat | Mitigation | File Reference |
|---|---|---|
| Audit log tampering | Events are INSERT-only; no UPDATE or DELETE path exists in the library. Rows carry a `created_at` timestamp set by the storage layer. A second copy is pushed to the operator-configured SIEM sink. | `internal/audit/service.go:400` |
| Webhook body forgery | HMAC-SHA256 signature in `X-CloudEvents-Signature` header; recipient should verify with `hmac.Equal` (constant-time). | `audit/sinks/webhook/webhook.go:131` |

**Information Disclosure**

| Threat | Mitigation | File Reference |
|---|---|---|
| Secrets in audit metadata | Default redactor strips `password`, `secret`, `token`, `code`, `refresh_token`, `access_token` (case-insensitive) at any nesting depth before emission (`audit.go:15-40`). Custom redactor is applied first, then the default redactor, so a custom redactor cannot re-introduce secrets (`internal/audit/service.go:281-283`). | `audit.go:15-40`; `internal/audit/service.go:281-283` |

**Denial of Service**

| Threat | Mitigation | File Reference |
|---|---|---|
| Slow sink blocks event processing | Sinks run in separate goroutines; a slow or unavailable sink does not block the application's hot path. Flush errors are logged but do not propagate to the caller. | `internal/audit/service.go:400` |

---

## Session Subsystem

### Trust Boundaries

- Session token is a `crypto/rand` opaque value stored as SHA-256 hash in the database.
- Token is transmitted as an HttpOnly cookie.

### STRIDE Analysis

**Spoofing**

| Threat | Mitigation | File Reference |
|---|---|---|
| Session token brute-force | Tokens are 32-byte crypto/rand values; SHA-256 stored. Brute-force infeasible. | `crypto/tokens.go` |
| Session fixation | A new session token is minted on every authentication level promotion (password login, MFA completion, OAuth callback). The previous token is not reused. | `internal/session/service.go`; `internal/oauth/handlers/handlers.go:122` |

**Information Disclosure**

| Threat | Mitigation | File Reference |
|---|---|---|
| Cookie theft via XSS | All session cookies are `HttpOnly` and `SameSite=Lax` (`handlers.go:147,183`). `Secure` flag is set when `SecureCookie=true` (`theauth.go:40`). A runtime warning is emitted when `SecureCookie=false` (`theauth.go:41-45`). | `handlers.go:147,183`; `theauth.go:40-45` |

---

## Agent Identity Flow

### Trust Boundaries

- Machine clients authenticate with `client_id` + `client_secret`; secret is Argon2id-hashed.
- Agents issue tokens via the `client_credentials` grant.

### STRIDE Analysis

**Spoofing**

| Threat | Mitigation | File Reference |
|---|---|---|
| Stolen agent secret | Secret stored as Argon2id PHC; verified with `subtle.ConstantTimeCompare` via the `clientauthcache`. Cache is invalidated when agent is suspended or revoked (`internal/agent/service.go:444`). | `internal/agent/service.go:444`; `internal/clientauthcache/cache.go:165` |

**Elevation of Privilege**

| Threat | Mitigation | File Reference |
|---|---|---|
| Agent issuing tokens beyond its permitted scope | `client_credentials` token scope is bounded to the agent's registered scope list (`internal/as/token_v34.go:44-124`). | `internal/as/token_v34.go:44-124` |
| Suspended/revoked agent token still valid | Introspection re-walks the agent status on every call; `InvalidateChainCache` is called on suspend/revoke so cached validation results are dropped (`internal/as/service.go:138,310`). | `internal/as/service.go:138,310` |

---

## Delegation Chains

### Trust Boundaries

- An agent acting on behalf of a user (RFC 8693 token exchange) carries a delegation grant that specifies the permitted scope.

### STRIDE Analysis

**Elevation of Privilege**

| Threat | Mitigation | File Reference |
|---|---|---|
| Scope escalation through delegation | `NarrowScope` computes the strict intersection of requested scope, subject scope, and grant scope (`internal/delegation/service.go:263-291`). An empty result is treated as `invalid_scope`. | `internal/delegation/service.go:263-291` |
| Revoked delegation grant still usable | Introspection checks the grant's revocation status; a revoked grant causes token rejection (`internal/as/introspect.go:161`). | `internal/as/introspect.go:161` |

---

## CIMD (Client Identity Metadata Document)

### Trust Boundaries

- The AS fetches a JSON document from an HTTPS URL supplied as the `client_id`.
- The document is cached in process memory for the configured `CacheTTL`.

### STRIDE Analysis

**Spoofing**

| Threat | Mitigation | File Reference |
|---|---|---|
| Attacker-controlled metadata document | `TrustPolicy` gates every fetch; default is `DenyAll` (fail-closed) (`internal/cimd/service.go:114-115`). Operator must explicitly configure `AllowAnyHTTPS()` or `AllowHTTPSHost(...)` to permit fetches. | `internal/cimd/service.go:114-115` |

**Server-Side Request Forgery**

| Threat | Mitigation | File Reference |
|---|---|---|
| CIMD URL points to internal metadata service | `LooksLikeCIMD` requires scheme `https` and a non-empty host (`internal/cimd/service.go:224-245`). HTTP and non-HTTPS schemes are rejected outright. `TrustPolicy` provides a second gate for allowlisting specific hosts. | `internal/cimd/service.go:224-245` |

**Residual risk:** The library does not enumerate and block all RFC 1918 private address ranges. Operators using `AllowAnyHTTPS()` in environments where internal HTTPS services exist should additionally configure a host allowlist (`AllowHTTPSHost`).

---

## Threat Catalog

The following threats are referenced in the summary above. For procurement, this table maps each named threat to its mitigation status.

| ID | Threat | Status | Key Code Reference |
|---|---|---|---|
| T-01 | Token theft / bearer replay | Mitigated (DPoP) | `internal/as/token.go:234-245` |
| T-02 | Token replay across resources | Mitigated (cnf.jkt + aud) | `internal/as/token.go:234-245`; `mcpresource/validator.go` |
| T-03 | PKCE downgrade | Mitigated (S256 only) | `crypto/pkce.go`; `internal/as/token.go:99-103` |
| T-04 | Authorization code injection | Partially mitigated (PKCE + state); PAR planned | `internal/as/token.go:99-103`; `internal/as/config.go:102-107` |
| T-05 | Open redirect on /authorize | Mitigated (redirect_uri whitelist) | `internal/as/dcr.go:206-228`; `internal/as/token.go:92-93` |
| T-06 | CSRF on /authorize | Mitigated when `RequireState=true` | `internal/as/config.go:102-107` |
| T-07 | Session fixation | Mitigated (new token on level promotion) | `internal/session/service.go`; `internal/oauth/handlers/handlers.go:122` |
| T-08 | Refresh token replay | Mitigated (family revocation per RFC 9700) | `internal/as/token.go:122-176` |
| T-09 | Argon2 work-factor downgrade | Mitigated (params in PHC string; configurable) | `crypto/password.go:23,62-84` |
| T-10 | JWKS rotation race | Mitigated (atomic rotation when adapter supports it) | `internal/as/jwks.go:295-338` |
| T-11 | Audit log tampering | Partially mitigated (INSERT-only + SIEM sink) | `internal/audit/service.go:400` |
| T-12 | clientauthcache poisoning | Mitigated (invalidated on suspend/revoke) | `internal/clientauthcache/cache.go:165` |
| T-13 | SCIM token reuse | Partially mitigated (last_used_at tracking) | `internal/scim/service.go:117-138` |
| T-14 | Webhook signature forgery | Mitigated (HMAC-SHA256) | `audit/sinks/webhook/webhook.go:131` |
| T-15 | Cookie theft | Mitigated (HttpOnly, SameSite=Lax, Secure flag) | `handlers.go:147,183`; `theauth.go:40-45` |
| T-16 | SAML signature wrapping | Mitigated (crewjam/saml + goxmldsig) | `go.mod:7,14`; `internal/saml/service.go:41` |
| T-17 | WebAuthn replay | Mitigated (sign counter monotonic check) | `internal/webauthn/service.go:108,431-436` |
| T-18 | MFA bypass on identity merge | Mitigated (step-up required) | `internal/identitylink/service.go:72-84`; `internal/models/errors.go:177-181` |
| T-19 | Provider OAuth state CSRF | Mitigated (state cookie + comparison) | `internal/oauth/handlers/handlers.go:101-109` |
| T-20 | CIMD trust policy bypass | Mitigated (DenyAll default) | `internal/cimd/service.go:114-115` |
| T-21 | Apple .p8 key leak | Operator responsibility (documented) | `provider/apple/apple.go:8-18` |
| T-22 | SSRF via CIMD metadata URL | Partially mitigated (HTTPS-only; host allowlist recommended) | `internal/cimd/service.go:224-245` |
| T-23 | Delegation scope escalation | Mitigated (scope intersection) | `internal/delegation/service.go:263-291` |
