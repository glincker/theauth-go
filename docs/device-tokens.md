# Device tokens (constrained device identity)

Phase 0 of IoT support: give each constrained device (sensor, gateway, microcontroller with a secure element) its own key, enroll it once with an admin-minted join token, and let it exchange a self-signed assertion for a short-lived access token. No client secret lives on the device, and no refresh token is issued.

This is separate from the RFC 8628 device authorization grant ([device-authorization.md](device-authorization.md)), which signs a *user* in on a browserless client. Here the device itself is the principal.

```go
auth, err := theauth.New(theauth.Config{
    Storage: store, // memory, Postgres or MySQL (migration 0024)
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

The storage must implement `theauth.DeviceIdentityStorage`; `New` fails with `ErrStorageMissingCapability` otherwise. SQLite does not implement it.

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

## 2. Enroll

The device proves it holds the private key for the public JWK it submits. Two calls, both unauthenticated and rate limited:

```
POST /oauth/devices/challenge
{"join_token": "dj_...", "jwk": {"kty":"EC","crv":"P-256","x":"...","y":"..."}}
-> 200 {"challenge": "<server signed JWT>", "expires_in": 120}

POST /oauth/devices/enroll
{"join_token": "dj_...", "jwk": {...}, "challenge": "<from above>", "proof": "<JWS>"}
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

Assertion claims: `iss` and `sub` equal to the device ID, `aud` equal to the token endpoint URL (`{issuer}/oauth/token`), `iat`, `exp` no more than `AssertionMaxLifetime` after `iat`, and a unique `jti`. The server verifies the signature against the enrolled key, then records the `jti` for replay protection. The replay record is only written after the signature verifies, so unauthenticated callers cannot fill it.

Response:

```json
{"access_token": "...", "token_type": "Bearer", "expires_in": 600, "scope": "telemetry:write"}
```

Token claims: `sub` is the SPIFFE ID, or `device:<id>` when none was assigned; `client_id` and `device_id` are the device ID; `aud` is the resource; `organization_id` is set when the device has one.

When the request carries a valid DPoP proof, the token gets `cnf.jkt` and `token_type` is `DPoP` (RFC 9449). A bad proof is refused with `invalid_dpop_proof` before the assertion `jti` is spent, so the device can retry the same assertion.

The jwt-bearer grant is dispatched to the device path only when `iss` is the ID of a registered device. Assertions from `JWTBearer.TrustedJWTIssuers` are unaffected.

## Revocation

```go
err := auth.RevokeDevice(ctx, deviceID)
```

From then on the device's assertions fail with `invalid_grant`, and `/oauth/introspect` reports every token already issued to it as `active: false`, including answers that would otherwise come from the introspection cache.

Resource servers that verify JWTs offline (`mcpresource` with a JWKS URL) do not see revocation until the token expires. The 10 minute default bounds that window; shorten `AccessTokenTTL` or introspect on sensitive calls when it matters.

## Admin API

With `Config.Admin` and RBAC enabled, under `/admin/v1/organizations/{orgID}`, gated by `agents:admin`:

```
POST   /devices/join-tokens         {"name","spiffe_id","scopes","ttl_seconds"} -> 201, includes "token" once
DELETE /devices/join-tokens/{id}    -> 204
GET    /devices                     -> {"data": [...]}   (this organization's devices, no key material)
POST   /devices/{id}/revoke         -> 204
```

Programmatic equivalents: `CreateDeviceJoinToken`, `RevokeDeviceJoinToken`, `ListDevices`, `RevokeDevice`.

Audit events: `device.join_token.created`, `device.enrolled`, `device.token_minted`, `device.revoked`.

## Extending attestation

Enrollment goes through an internal `Attestor` interface (`Attest`, `Consume`, `Release`). The built-in `join_token` attestor is the only one wired today; X.509 proof of possession and TPM attestors can implement the same interface later.

## Storage

Migration 0024 (Postgres, MySQL) adds `iot_devices` and `device_join_tokens`. The Postgres migration has a matching down file. Run `storagetest.RunDeviceIdentity` against a custom `DeviceIdentityStorage`.
