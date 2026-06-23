# Configuration Reference

The `theauth.Config` struct is the single wiring point for a theauth-go instance. Pass it to `theauth.New(cfg)`.

## Required fields

| Field | Type | Description |
|---|---|---|
| `Storage` | `theauth.Storage` | Persistence adapter. Use `memory.New()` for dev or `postgres.New(pool)` for production. |
| `BaseURL` | `string` | Absolute base URL of the application (e.g., `https://myapp.com`). Used in magic-link emails and OAuth redirect URIs. |

## Session and cookie settings

| Field | Type | Default | Description |
|---|---|---|---|
| `SessionTTL` | `time.Duration` | 24h | How long sessions remain valid. |
| `MagicLinkTTL` | `time.Duration` | 15m | How long magic-link tokens are valid. |
| `CookieName` | `string` | `"theauth_session"` | Session cookie name. |
| `SecureCookie` | `bool` | `false` | Set to `true` in production (requires HTTPS). |
| `SuppressSecureCookieWarning` | `bool` | `false` | Silence the startup warning when `SecureCookie` is false (useful in local dev). |

## Rate limiting

| Field | Type | Default | Description |
|---|---|---|---|
| `RateLimitPerIP` | `int` | 5 | Per-IP per-minute budget on credential endpoints. |
| `RateLimitPerEmail` | `int` | 3 | Per-email per-minute budget on signin and forgot. |
| `TrustedProxies` | `[]netip.Prefix` | `nil` | Reverse-proxy networks whose `X-Forwarded-For` is trusted. Default: no XFF trust. |

## Email

| Field | Type | Default | Description |
|---|---|---|---|
| `EmailSender` | `email.Sender` | `email.Noop{}` | Email delivery adapter. Implement `email.Sender` to deliver magic links and password reset emails. |

## OAuth providers

| Field | Type | Description |
|---|---|---|
| `Providers` | `[]theauth.Provider` | OAuth providers (github, google, microsoft, discord, or custom). |
| `EncryptionKey` | `[]byte` | 32-byte AES-256 key. Required when `Providers` is non-empty, `TOTP` is configured, or `AuthorizationServer` is configured. Source from a secrets manager. |
| `PostLoginRedirect` | `string` | Path to redirect to after OAuth sign-in. Defaults to `/`. |

## WebAuthn / passkeys

| Field | Type | Description |
|---|---|---|
| `WebAuthn` | `*WebAuthnConfig` | Passkey registration and discoverable login. Nil disables WebAuthn. |

```go
type WebAuthnConfig struct {
    RPDisplayName string
    RPID          string   // eTLD+1 of your domain
    RPOrigins     []string // full origin URL(s)
    ChallengeTTL  time.Duration // default 5m
}
```

## TOTP

| Field | Type | Description |
|---|---|---|
| `TOTP` | `*TOTPConfig` | TOTP second factor with recovery codes. Requires `EncryptionKey`. Nil disables TOTP. |

## Organizations (multi-tenancy)

| Field | Type | Description |
|---|---|---|
| `Organizations` | `*OrganizationsConfig` | Enable multi-tenancy. SAML and SCIM require this. Nil = single-tenant. |

## SAML 2.0

| Field | Type | Description |
|---|---|---|
| `SAML` | `*SAMLConfig` | SAML 2.0 Service Provider. Requires `Organizations`. |

## SCIM 2.0

| Field | Type | Description |
|---|---|---|
| `SCIM` | `*SCIMConfig` | SCIM 2.0 provisioning. Requires `Organizations`. |

## RBAC

| Field | Type | Description |
|---|---|---|
| `RBAC` | `*RBACConfig` | Organization-scoped roles and permissions. Required for `Admin`. |

```go
type RBACConfig struct {
    // ExtraPermissions extends the closed permission catalog.
    ExtraPermissions []string
    // ExtraRoleSeeds adds additional org roles beyond owner/admin/member.
    ExtraRoleSeeds []RoleSeed
}
```

## Audit log

| Field | Type | Description |
|---|---|---|
| `Audit` | `*AuditConfig` | Async batched audit writer. Nil = silent no-op. |

```go
type AuditConfig struct {
    // BufferSize is the channel depth (default 4096).
    BufferSize int
    // FlushTimeout is the Close() drain deadline (default 5s).
    FlushTimeout time.Duration
    // Redactor is called on every metadata map before storage.
    // Defaults to DefaultRedactor (masks password/secret/token/code fields).
    Redactor func(action string, metadata map[string]any)
}
```

## Admin API

| Field | Type | Description |
|---|---|---|
| `Admin` | `*AdminConfig` | Mount `/admin/v1/*`. Requires `RBAC`. |

```go
type AdminConfig struct {
    // PathPrefix overrides "/admin/v1" (must start with "/").
    PathPrefix string
}
```

## OAuth 2.1 Authorization Server (v2.0)

| Field | Type | Description |
|---|---|---|
| `AuthorizationServer` | `*AuthorizationServerConfig` | Enable the OAuth 2.1 AS. Requires `EncryptionKey` and a storage adapter satisfying `OAuthServerStorage`. |

```go
type AuthorizationServerConfig struct {
    // Issuer is the canonical AS identifier (RFC 8414). Required.
    Issuer string

    // Resources lists the protected resources this AS issues tokens for.
    // Each resource has an Identifier (URI) and Scopes.
    Resources []ProtectedResource

    // AllowAnonymousRegistration enables unauthenticated DCR (RFC 7591).
    // Default: false (deny all registration). Set true for public MCP.
    AllowAnonymousRegistration bool

    // RegistrationTokens are bearer tokens accepted for DCR when not anonymous.
    // Hashed at New time; compared with crypto/subtle.ConstantTimeCompare.
    RegistrationTokens []string

    // RegistrationRateLimitPerMinute caps POST /oauth/register per source IP.
    // Default: 1 when AllowAnonymousRegistration is true, 5 otherwise.
    // Negative value disables the cap.
    RegistrationRateLimitPerMinute int

    // AccessTokenTTL is the JWT access token lifetime (default 15m).
    AccessTokenTTL time.Duration

    // RefreshTokenTTL is the refresh token lifetime (default 30d).
    RefreshTokenTTL time.Duration

    // IntrospectionCacheTTL is how long introspection results are cached
    // in the mcpresource validator (default 60s).
    IntrospectionCacheTTL time.Duration

    // RequireState rejects /authorize requests that omit a non-empty state
    // parameter (RFC 9700 best-current-practice). Default: false.
    RequireState bool

    // PAR configures Pushed Authorization Requests (RFC 9126, v2.4).
    // Nil disables PAR.
    PAR *PARConfig

    // JAR configures JWT-Secured Authorization Requests (RFC 9101, v2.4).
    // Nil disables JAR.
    JAR *JARConfig

    // JWTBearer configures JWT-Bearer client auth and grant (RFC 7523, v2.4).
    // Nil disables JWT-Bearer.
    JWTBearer *JWTBearerConfig

    // CIBA configures Client-Initiated Backchannel Authentication (RFC 9509, v2.4).
    // Nil disables CIBA.
    CIBA *CIBAConfig
}

// PARConfig controls Pushed Authorization Request behaviour (v2.4).
type PARConfig struct {
    // Required rejects plain /authorize requests that do not use request_uri.
    // Set true for FAPI 2.0 profiles.
    Required bool
    // TTL is the lifetime of the request_uri handle (default: 60s).
    TTL time.Duration
}

// JARConfig controls JWT-Secured Authorization Request behaviour (v2.4).
type JARConfig struct {
    // Required rejects /authorize requests that do not carry a signed
    // request JWT. Set true for FAPI 2.0 profiles.
    Required bool
    // AllowedAlgorithms limits accepted signing algorithms.
    // Default: ES256, RS256.
    AllowedAlgorithms []string
}

// JWTBearerConfig controls JWT-Bearer client auth and grants (v2.4, RFC 7523).
type JWTBearerConfig struct {
    // TrustedIssuers lists external OIDC/JWT issuers trusted for jwt-bearer
    // grant assertions.
    TrustedIssuers []TrustedJWTIssuer
}

// TrustedJWTIssuer represents one external JWT issuer for jwt-bearer grants.
type TrustedJWTIssuer struct {
    // Issuer is the expected "iss" claim value.
    Issuer string
    // JWKSU is the JWKS endpoint URL for this issuer.
    JWKSU string
    // SubjectMapper maps the JWT claims to a theauth client_id.
    // Return ("", nil) to deny silently.
    SubjectMapper func(ctx context.Context, claims map[string]any) (string, error)
}

// CIBAConfig controls Client-Initiated Backchannel Authentication (v2.4, RFC 9509).
type CIBAConfig struct {
    // AuthenticationDevice delivers the out-of-band auth request to the user.
    // Required.
    AuthenticationDevice AuthenticationDevice
    // ExpiresIn is the auth_req_id lifetime (default: 120s).
    ExpiresIn time.Duration
    // PollingInterval is the minimum client poll interval in seconds (default: 5).
    PollingInterval int
}
```

## Password policy (v2.4)

| Field | Type | Description |
|---|---|---|
| `PasswordPolicy` | `*PasswordPolicyConfig` | Additional password handling options. Nil uses defaults. |

```go
type PasswordPolicyConfig struct {
    // AllowLegacyBcrypt accepts bcrypt-hashed passwords during the migration
    // window when migrating from Auth0 or similar systems. On a successful
    // bcrypt login, theauth-go re-hashes with Argon2id.
    // Disable this flag once the migration window closes.
    // Default: false.
    AllowLegacyBcrypt bool

    // OnLegacyHashAccepted is called after a successful bcrypt verify with the
    // new Argon2id hash. Use this to persist the updated hash to storage.
    // Called in a background goroutine; the login response is not delayed.
    OnLegacyHashAccepted func(userID string, newArgon2idHash string)
}
```

## Agent identity and delegation (v2.0)

| Field | Type | Description |
|---|---|---|
| `AgentIdentity` | `*AgentConfig` | Enable agent CRUD and RFC 8693 token exchange. Requires `AuthorizationServer`. |

```go
type AgentConfig struct {
    // MaxChainDepth is the max act-chain length. Hard ceiling: 3.
    MaxChainDepth int

    // MaxDelegationDuration caps delegation grant duration (default 90d).
    MaxDelegationDuration time.Duration

    // DefaultDelegatedTokenTTL is the default TTL for exchanged tokens (default 15m).
    DefaultDelegatedTokenTTL time.Duration

    // AgentSecretLength is the one-time secret length in bytes (default 32).
    AgentSecretLength int
}
```

| Field | Type | Description |
|---|---|---|
| `AccountUX` | `bool` | Mount `/account/agents` and `/account/delegations`. Requires `AgentIdentity`. |

## Observability

| Field | Type | Description |
|---|---|---|
| `Observability` | `*theauth.Hooks` | Wire tracing and metrics adapters. Nil = no-op. |

```go
type Hooks struct {
    Tracer  Tracer  // span emitter
    Metrics Metrics // counter/histogram/gauge factory
}
```

See [Wire OpenTelemetry Tracing](../guides/opentelemetry-tracing.md) and [Metrics Reference](metrics.md) for details.
