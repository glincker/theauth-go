# Per-client access token policy

By default every client gets a JWT signed with Ed25519 (EdDSA). Some resource servers cannot verify EdDSA, and some deployments do not want tokens that carry claims in the clear. `TokenPolicy` lets each client pick.

## Enable

```go
AuthorizationServer: &theauth.AuthorizationServerConfig{
    Issuer:    "https://auth.example.com",
    Resources: []theauth.ProtectedResource{{Identifier: "https://api.example.com", Scopes: []string{"read"}}},
    TokenPolicy: &theauth.TokenPolicyConfig{
        SigningAlgs:              []string{"ES256", "RS256"}, // extra algs clients may choose
        DefaultAccessTokenFormat: theauth.AccessTokenFormatJWT, // or AccessTokenFormatOpaque
    },
}
```

`AuthorizationServerConfig.SigningAlg` still sets the server default and now accepts `EdDSA`, `ES256` or `RS256`. Nothing changes for clients that do not ask for anything.

## Client metadata

Two fields on dynamic registration (and on `OAuthClient` for clients you create yourself):

| Field | Values |
|---|---|
| `access_token_signed_response_alg` | `EdDSA`, `ES256`, `RS256`. Must be the default or listed in `SigningAlgs`. |
| `access_token_format` | `jwt` or `opaque`. `opaque` needs `TokenPolicy` and a storage that implements `theauth.OpaqueTokenStorage`. |

```json
POST /oauth/register
{"redirect_uris": ["https://app.example.com/cb"],
 "access_token_signed_response_alg": "RS256"}
```

Anonymous registrations cannot set either field, because they choose server side behaviour (key generation, token storage). Registration fails with `invalid_client_metadata` if the value is not enabled.

## Keys

The first time a client needs an algorithm the server mints a current and a next key for it. `/oauth/jwks` publishes all of them, each with its own `alg` and `kid`. Rotation (`RotateSigningKey` and the background loop) moves every algorithm through current, previous and retired together. Tokens signed before a rotation keep verifying until their key is retired.

RS256 keys are 2048 bit RSA. ES256 uses P-256. Private keys are stored AES-GCM encrypted, like the Ed25519 seed.

Verification resolves the key by `kid` and then requires the key type to match the `alg` in the header. `none` and the HMAC algorithms are never accepted.

## Opaque tokens

An opaque token is 32 random bytes, base64url encoded. The server stores only its SHA-256 hash and the claim set a JWT would have carried. Resource servers cannot decode it, so they must call `/oauth/introspect`, which answers exactly as it does for a JWT (including `authorization_details`, `cnf` and the actor chain checks).

Revocation works without the `AccessTokenRevocation` denylist: `POST /oauth/revoke` marks the row revoked, and only the client the token was issued to can do it. Introspection results are cached for `IntrospectionCacheTTL`, so another replica can keep answering `active` for that long after a revoke. The instance that handled the revoke clears its cache immediately.

Storage: memory, Postgres and MySQL (migration `0021`) implement it. Run `storagetest.RunOpaqueTokens` against your own adapter. Expired rows are not removed for you; delete rows past `expires_at` from a job.

## Not included

Resource servers using the `mcpresource` package keep validating Ed25519 tokens locally. For other algorithms or opaque tokens, use introspection.
