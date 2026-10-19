# Device tokens (constrained device identity)

Phase 0 of IoT support: give each constrained device (sensor, gateway, microcontroller with a secure element) its own key, enroll it once with an admin-minted join token, and let it exchange a self-signed assertion for a short-lived access token. No client secret lives on the device, and no refresh token is issued.

This is separate from the RFC 8628 device authorization grant ([device-authorization.md](device-authorization.md)), which signs a *user* in on a browserless client. Here the device itself is the principal.

```go
auth, err := theauth.New(theauth.Config{
    Storage: store, // memory, SQLite (migration 0011), Postgres or MySQL (migration 0024)
    AuthorizationServer: &theauth.AuthorizationServerConfig{
        Issuer:    "https://auth.example.com",
        Resources: []theauth.ProtectedResource{{Identifier: "https://iot.example.com/api", Scopes: []string{"telemetry:write", "config:read"}}},
        DeviceTokens: &theauth.DeviceTokensConfig{
            AccessTokenTTL: 10 * time.Minute, // default
        },
        DPoP: &theauth.DPoPConfig{}, // optional, binds tokens to a proof key
    },
})
```

`DeviceTokensConfig` fields, all optional:

| Field | Default | Meaning |
| --- | --- | --- |
| `AccessTokenTTL` | 10m | Lifetime of device access tokens |
| `JoinTokenTTL` | 1h | Default join token lifetime |
| `ChallengeTTL` | 2m | How long an enrollment challenge is valid |
| `AssertionMaxLifetime` | 5m | Cap on `exp - iat` of an assertion |
| `EnrollPerMinute` | 10 | Challenge plus enroll requests per join token per minute, negative disables |
| `TokenPerMinute` | 60 | Assertion grants per device per minute, negative disables |
| `Attestation` | none | `*DeviceAttestationConfig{Required, Verify}`: hardware attestation evidence at enrollment, see [device-attestation.md](device-attestation.md) |

The storage must implement `theauth.DeviceIdentityStorage`; `New` fails with `ErrStorageMissingCapability` otherwise. Memory, Postgres (migration 0024), MySQL and SQLite (migration 0011 of `storage/sqlite`) implement it.

## Rate limits

Both budgets are per identity, on top of the per IP and per client limits of `ASRateLimits`. Over budget the endpoint answers `429 rate_limited` with `Retry-After`. The shared limiter (`Config.Stores.RateLimiter`) holds the counters, so replicas share them.

- `TokenPerMinute` is charged only after the assertion signature verified. Someone who only knows a device ID cannot use up its budget, and a limited assertion is not spent, so the device can retry the same one.
- `EnrollPerMinute` is charged per join token, and only for join tokens that exist and are usable, so unknown or spent tokens fall through to `invalid_grant` without touching a bucket. A device that has not enrolled yet has no device ID, which is why the join token is the identity here.

## 1. Mint a join token

An admin mints one join token per device. The token fixes the identity the device receives, so a device cannot pick its own name, SPIFFE ID or scopes.

```go
tok, secret, err := auth.CreateDeviceJoinToken(ctx, theauth.CreateDeviceJoinTokenInput{
    OrganizationID: &orgID,
    Name:           "boiler room sensor",
    SPIFFEID:       "spiffe://example.org/site-1/boiler",
    Scopes:         []string{"telemetry:write"}, // required, capped by the resource's scopes
    TTL:            time.Hour,
})
// provision `secret` (prefix dj_) onto the device; it is not recoverable
```

Only a SHA-256 digest is stored. A token enrolls exactly one device and then stays spent.

### Claim codes and bulk tokens

`Kind` picks the shape of the token. The identity fields (`Name`, `Scopes`, `OrganizationID`) work the same for all three.

| Kind | Secret | Devices | Default TTL |
| --- | --- | --- | --- |
| `theauth.DeviceJoinTokenSingle` (empty) | `dj_...` | 1 | `JoinTokenTTL` |
| `theauth.DeviceJoinTokenClaim` | `XXXXX-XXXXX` | 1 | 15m |
| `theauth.DeviceJoinTokenBulk` | `dj_...` | `MaxUses`, 1 to 1,000,000 | 24h |

A claim code is 10 characters of Crockford base32 (50 bits), meant for a person to type: case, dashes and spaces are ignored, and `I`, `L` and `O` read as `1`, `1` and `0`. Keep its TTL short. A bulk token is for a factory line: every device it enrolls gets the same name and scopes, so it cannot fix a `SPIFFEID` (a SPIFFE ID is unique, and `MaxUses` above 1 with one is refused). Claim codes and bulk tokens live at most 30 days.

```go
_, code, _ := auth.CreateDeviceJoinToken(ctx, theauth.CreateDeviceJoinTokenInput{
    Kind: theauth.DeviceJoinTokenClaim, OrganizationID: &orgID, Scopes: []string{"telemetry:write"},
})
// code looks like 7XK2M-9QD4F; the device sends it as join_token

_, line, _ := auth.CreateDeviceJoinToken(ctx, theauth.CreateDeviceJoinTokenInput{
    Kind: theauth.DeviceJoinTokenBulk, MaxUses: 500, OrganizationID: &orgID,
    Name: "line 3", Scopes: []string{"telemetry:write"}, TTL: 48 * time.Hour,
})
```

Every enrollment spends one use with a single conditional update on each store, so a token with `MaxUses: 500` never enrolls 501 devices, whatever the concurrency. A use is given back only when the registration insert fails afterwards. Claim codes are hashed under their own domain, so a code can never be replayed as a `dj_` token.

## 2. Enroll

The device proves it holds the private key for the public JWK it submits. Two calls, both unauthenticated and rate limited:

```
POST /oauth/devices/challenge
{"join_token": "dj_...", "jwk": {"kty":"EC","crv":"P-256","x":"...","y":"..."}}
-> 200 {"challenge": "<server signed JWT>", "expires_in": 120, "nonce": "<jti of the challenge>"}

POST /oauth/devices/enroll
{"join_token": "dj_...", "jwk": {...}, "challenge": "<from above>", "proof": "<JWS>", "attestation_evidence": "<optional, see device-attestation.md>"}
-> 201 {"device_id": "...", "subject": "spiffe://...", "name": "...", "scope": [...]}
```

The `proof` is a JWS signed with the device key: header `typ: device-enroll+jwt`, `alg` matching the key, claims `aud` (the issuer), `iat`, `exp`, and `nonce` set to the `jti` of the challenge. The server checks the challenge signature and key binding, verifies the proof with the submitted key, then spends the join token atomically and registers the device.

Supported keys: EC P-256 (`ES256`), EC P-384 (`ES384`) and Ed25519 (`EdDSA`). JWKs carrying private members are refused. A failed proof does not spend the token.

Every failure answers `400 invalid_grant` without saying which check failed. A SPIFFE ID already in use answers `409`.

## 3. Get a token (RFC 7523)

The device signs an assertion with its enrolled key and posts it to the token endpoint:

```
POST /oauth/token
grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer
assertion=<JWS>
resource=https://iot.example.com/api   (optional with exactly one configured resource)
scope=telemetry:write                  (optional, defaults to the device's scopes)
DPoP: <proof>                          (optional)
```

Assertion claims: `iss` and `sub` equal to the device ID, `aud` equal to the token endpoint URL (`{issuer}/oauth/token`), `iat`, `exp` no more than `AssertionMaxLifetime` after `iat`, and a unique `jti` of at least 16 characters (the TypeScript device module requires the same). The server verifies the signature against the enrolled key, then records the `jti` for replay protection. The replay record is only written after the signature verifies, so unauthenticated callers cannot fill it.

Response:

```json
{"access_token": "...", "token_type": "Bearer", "expires_in": 600, "scope": "telemetry:write"}
```

Token claims: `sub` is the SPIFFE ID, or `device:<id>` when none was assigned; `client_id` and `device_id` are the device ID; `aud` is the resource; `organization_id` is set when the device has one.

When the request carries a valid DPoP proof, the token gets `cnf.jkt` and `token_type` is `DPoP` (RFC 9449). A bad proof is refused with `invalid_dpop_proof` before the assertion `jti` is spent, so the device can retry the same assertion.

The jwt-bearer grant is dispatched to the device path only when `iss` is the ID of a registered device. Assertions from `JWTBearer.TrustedJWTIssuers` are unaffected.

## Suspend and resume

```go
err := auth.SuspendDevice(ctx, deviceID) // a hold: no tokens until resumed
err = auth.ResumeDevice(ctx, deviceID)
```

A suspended device gets `invalid_grant` at the token endpoint and `/oauth/introspect` reports its tokens inactive, exactly as for a revoked one, but `ResumeDevice` brings it back. Both calls are idempotent, and a revoked device is permanent: `SuspendDevice` and `ResumeDevice` return `theauth.ErrDeviceRevoked` for it (the admin routes answer 409). Each change is a conditional update, so concurrent callers cannot undo a revoke. `DeviceTokensConfig.OnStatusChange(ctx, deviceID, status)` runs after a suspend or resume, with `suspended` or `active`; `mqttauth.Purger.OnStatusChange` fits. Audit events: `device.suspended`, `device.resumed`.

## Revocation

```go
err := auth.RevokeDevice(ctx, deviceID)
```

From then on the device's assertions fail with `invalid_grant`, and `/oauth/introspect` reports every token already issued to it as `active: false`, including answers that would otherwise come from the introspection cache.

`DeviceTokensConfig.OnRevoke` is called with the device ID after every successful revoke, from the Go method and from the admin route. Use it to drop caches in your own services. For an MQTT broker, `mqttauth.Purger` plugs in here (see [mqtt-auth.md](mqtt-auth.md)), together with `mqtt:<action>:<levels>` scopes that become the device's topic ACL.

Resource servers that verify JWTs offline (`mcpresource` with a JWKS URL) do not see revocation until the token expires. The 10 minute default bounds that window; shorten `AccessTokenTTL` or add a revocation check.

`mcpresource` has an optional, off by default hook for this, applied after signature, audience, expiry and DPoP checks:

```go
v := mcpresource.New("https://iot.example.com/api",
    mcpresource.WithJWKS("https://auth.example.com/oauth/jwks"),
    mcpresource.WithIntrospection("https://auth.example.com/oauth/introspect", clientID, clientSecret),
    mcpresource.WithDeviceRevocationIntrospection(), // introspects tokens that carry device_id
)
```

`WithDeviceRevocationIntrospection` calls the introspection endpoint only for tokens with a `device_id` claim and caches the answer for `WithCacheTTL`. For a denylist you own, pass your own checker instead:

```go
mcpresource.WithRevocationChecker(mcpresource.RevocationCheckerFunc(
    func(ctx context.Context, token string, p *mcpresource.Principal) (bool, error) {
        return denylist.Has(ctx, p.JWTID), nil // p.DeviceID is set for device tokens
    }))
```

A revoked token gets `401 invalid_token`. If the checker returns an error the request is refused; `WithRevocationFailOpen()` lets it through instead.

## Admin API

With `Config.Admin` and RBAC enabled, under `/admin/v1/organizations/{orgID}`, gated by `agents:admin`:

```
POST   /devices/join-tokens         {"name","spiffe_id","scopes","ttl_seconds","kind","max_uses"} -> 201, includes "token" once
DELETE /devices/join-tokens/{id}    -> 204
GET    /devices                     -> {"data": [...]}   (this organization's devices, no key material)
POST   /devices/{id}/revoke         -> 204
POST   /devices/{id}/suspend        -> 204   (409 when the device is revoked)
POST   /devices/{id}/resume         -> 204   (409 when the device is revoked)
```

`kind` is empty, `claim` or `bulk`; `bulk` needs `max_uses`. The response also carries `kind` and `max_uses`.

Programmatic equivalents: `CreateDeviceJoinToken`, `RevokeDeviceJoinToken`, `ListDevices`, `RevokeDevice`, `SuspendDevice`, `ResumeDevice`.

Audit events: `device.join_token.created`, `device.enrolled`, `device.enroll.attestation_refused`, `device.token_minted`, `device.revoked`, `device.suspended`, `device.resumed`.

## Extending attestation

Enrollment goes through an internal `Attestor` interface (`Attest`, `Consume`, `Release`). The built-in `join_token` attestor is the only one wired today.

Hardware evidence is a separate, configurable check: `DeviceTokensConfig.Attestation` runs a verifier from `iot/attest` (Android Key Attestation, Apple App Attest, TPM 2.0 quotes) after the proof of possession and before the join token is spent. See [device-attestation.md](device-attestation.md).

## Storage

Migration 0024 (Postgres, MySQL) and 0011 (SQLite) add `iot_devices` and `device_join_tokens`. Migration 0036 (Postgres, MySQL) and 0039 (SQLite) add the `max_uses` and `uses` columns of join tokens (existing rows read as one use of one) and an index on `key_thumbprint`. The Postgres migrations have matching down files. Run `storagetest.RunDeviceIdentity` against a custom `DeviceIdentityStorage`; it covers suspend and resume, the lookups and the multi use race.

Besides CRUD, `DeviceIdentityStorage` has `SuspendDevice` and `ResumeDevice` (conditional status updates that report whether they changed a row, and never touch a revoked device) and the indexed lookups `DeviceBySPIFFEID` and `DeviceByKeyThumbprint` (`ErrStorageNotFound` on a miss, the newest device when several share a key). `RedeemDeviceJoinToken` spends one use and `RefundDeviceJoinToken` gives one back.
