# Rich Authorization Requests (RFC 9396)

Scopes say "files.read". Some APIs need more: pay this amount to this account, read these records. `authorization_details` carries that as structured JSON from the authorize request into the access token.

## Enable

```go
AuthorizationServer: &theauth.AuthorizationServerConfig{
    Issuer:    "https://auth.example.com",
    Resources: []theauth.ProtectedResource{{Identifier: "https://bank.example.com", Scopes: []string{"pay"}}},
    RAR: &theauth.RARConfig{
        Types:      []string{"payment", "account_information"}, // required
        MaxDetails: 16,                                         // optional, default 16
    },
}
```

Without `RAR`, a request that carries `authorization_details` is refused with `invalid_authorization_details`.

## Request

```
GET /oauth/authorize?response_type=code&client_id=...&resource=https://bank.example.com
    &scope=pay&code_challenge=...&code_challenge_method=S256
    &authorization_details=[{"type":"payment","actions":["initiate"],
        "locations":["https://bank.example.com"],"instructedAmount":{"currency":"EUR","amount":"123.50"}}]
```

The same parameter works in a PAR body and as a claim inside a JAR request object. The value must be a JSON array of objects, each with a `type` from `RAR.Types`. The common members (`locations`, `actions`, `datatypes`, `identifier`, `privileges`) are checked for shape. Anything else, like `instructedAmount` above, is kept as is. Values over 16 KiB or with more than `MaxDetails` entries are refused.

## What comes back

The token response, the access token (as an `authorization_details` claim) and the introspection response all carry the details the user approved:

```json
{"access_token": "...", "token_type": "Bearer", "scope": "pay",
 "authorization_details": [{"type": "payment", "actions": ["initiate"], "...": "..."}]}
```

The details are stored with the authorization code and the refresh token family, so a refresh keeps them.

## Narrowing on refresh

A refresh or code exchange request may send `authorization_details` to ask for less. Each requested object must be covered by a granted object of the same type: list members (`actions`, `locations`, `datatypes`, `privileges`) must be subsets, scalar members must be equal. Anything broader fails with `invalid_authorization_details`. An omitted member inherits the grant, so asking for the type alone returns the full grant for it, never more. The narrowed set becomes the new refresh token's grant, so narrowing cannot be undone.

Other grants (client credentials, token exchange, jwt-bearer, device, CIBA) reject the parameter instead of ignoring it.

## Per client limits

`authorization_details_types` on client registration limits which types a client may request. Registration fails if a type is not in `RAR.Types`. Leave it empty to allow every server type.

## Metadata

`/.well-known/oauth-authorization-server` lists `authorization_details_types_supported` when RAR is on.

## Storage

Details travel in new columns (`authorization_details` on `oauth_authorization_codes` and `oauth_refresh_tokens`, plus three client columns), added by migration `0021` for Postgres and MySQL. Custom adapters should persist `AuthorizationCode.AuthorizationDetails`, `RefreshToken.AuthorizationDetails` and the three new `OAuthClient` fields. The `storagetest` suites check them.

## Not included

The server does not interpret types. Deciding what a `payment` object means, and showing it on a consent screen, is up to your application. Authorize requests are still approved by the logged in user without a consent step in this library.
