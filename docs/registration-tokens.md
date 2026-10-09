# Registration tokens (initial access tokens)

Dynamic client registration is either open to anyone (`AllowAnonymousRegistration`) or gated by the static `RegistrationTokens` list in config. Registration tokens add a third option for registering agents and other clients on demand: one-time or limited-use, scoped, expiring, stored hashed, and revocable.

```go
tok, secret, err := auth.CreateRegistrationToken(ctx, theauth.CreateRegistrationTokenInput{
    Label:      "build agent fleet",
    Scopes:     []string{"files.read"},                  // cap on the client's scope
    GrantTypes: []string{"client_credentials"},          // cap on its grant types
    MaxUses:    1,                                       // default 1
    TTL:        time.Hour,                               // default AuthorizationServerConfig.RegistrationTokenTTL (24h)
})
// hand `secret` to the agent now; it is not recoverable
```

The agent registers with it:

```
POST /oauth/register
Authorization: Bearer rt_...
{"client_name": "build agent", "grant_types": ["client_credentials"], "scope": "files.read"}
```

- A request that asks for more scope or grant types than the token allows gets `400 invalid_client_metadata` and does not use up the token.
- If registration then fails validation, the use is given back.
- Unknown, expired, revoked and used-up tokens all return `401 access_denied`, so the response does not say which.
- Only a SHA-256 digest is stored, plus a short prefix (`rt_ab12`) for recognizing tokens in lists.

Storage must implement `theauth.RegistrationTokenStorage` (memory, Postgres and MySQL do; migration 0019). Static config tokens keep working.

## Admin API

With `Config.Admin` and RBAC enabled, under `/admin/v1/organizations/{orgID}`, gated by the `agents:admin` permission:

```
POST   /registration-tokens        {"label","scopes","grant_types","max_uses","ttl_seconds"} -> 201, includes "token" once
GET    /registration-tokens        -> {"data": [...]}   (this organization's tokens, no secrets)
DELETE /registration-tokens/{id}   -> 204
```

Programmatic equivalents: `CreateRegistrationToken`, `ListRegistrationTokens`, `RevokeRegistrationToken`.

Audit events: `oauth.registration_token.created`, `.redeemed`, `.rejected` (scope exceeded) and `.revoked`.
