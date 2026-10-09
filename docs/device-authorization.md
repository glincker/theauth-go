# Device authorization grant (RFC 8628)

For CLIs, TVs and MCP clients that cannot open a browser. The device asks for a short code, the user approves it on a phone or laptop, and the device polls for tokens.

## Enable

```go
AuthorizationServer: &theauth.AuthorizationServerConfig{
    Issuer:    "https://auth.example.com",
    Resources: []theauth.ProtectedResource{{Identifier: "https://api.example.com", Scopes: []string{"deploy"}}},
    DeviceAuthorization: &theauth.DeviceAuthorizationConfig{}, // all fields optional
}
```

Storage must implement `theauth.DeviceAuthorizationStorage`. The memory, Postgres (migration 0019) and MySQL (migration 0019) adapters do. SQLite does not yet. Register the client with `grant_types: ["urn:ietf:params:oauth:grant-type:device_code"]`. Public clients (`token_endpoint_auth_method: none`) are fine, and CIMD clients work too.

The AS metadata gains `device_authorization_endpoint` and lists the grant.

## Flow

1. `POST /oauth/device_authorization` with `client_id`, `scope` and `resource` (optional when exactly one resource is configured). Returns `device_code`, `user_code`, `verification_uri`, `verification_uri_complete`, `expires_in` and `interval`.
2. The device shows the code and URL, then polls `POST /oauth/token` with `grant_type=urn:ietf:params:oauth:grant-type:device_code`, `device_code` and `client_id` every `interval` seconds.
3. The user opens `verification_uri_complete`, signs in if needed, checks the client name and scopes, and presses Allow or Deny.
4. Poll results follow RFC 8628: `authorization_pending`, `slow_down` (the interval grows by 5 seconds), `access_denied`, `expired_token`, then tokens. A `device_code` redeems once. DPoP works on the token request like any other grant.

## Verification page

`GET /oauth/device` renders minimal HTML. Anonymous browsers are redirected to `LoginURL` with a `next` parameter; anonymous JSON callers get `401`. Opening the link never approves anything; the user must press the button.

JSON API, for apps that bring their own UI (send `Accept: application/json` or a JSON body):

```
GET  /oauth/device?user_code=BCDF-GHJK   -> {"client_name": "...", "scope": "...", "expires_at": "..."}
POST /oauth/device {"user_code": "BCDF-GHJK", "action": "approve" | "deny" | "lookup"} -> {"status": "approved"}
```

Theming: the page uses CSS variables (`--bg --fg --muted --accent --danger --border`). Set `DeviceAuthorizationConfig.CSS` to override them, or set `Page` to render everything yourself from the `DevicePage` view model. The built-in page sends `frame-ancestors 'none'`, `X-Frame-Options: DENY` and `no-store`.

## Limits and storage

- `device_code` has 256 random bits. `user_code` is 8 letters from a 20 letter alphabet without vowels (about 34 bits) and is single use per request.
- Both are stored only as HMAC-SHA256 under a key derived from `EncryptionKey`, so a database leak does not reveal live codes and the short user code cannot be brute-forced offline.
- Code lookups on the verification page are limited per signed-in user (`MaxVerifyAttempts`, default 10 per 15 minutes). Every bad, expired or already decided code returns the same error.
- Defaults: 10 minute lifetime, 5 second interval. Change with `ExpiresIn` and `Interval`.
- Audit events: `oauth.device.requested`, `.approved`, `.denied`, `.redeemed`.
- Rows are not deleted automatically. Call `DeleteExpiredDeviceAuthorizations` from a job if the table grows.

See `examples/cli-device-login` for a stdlib-only CLI and a demo server.
