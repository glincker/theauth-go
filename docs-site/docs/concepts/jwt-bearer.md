# JWT-Bearer Client Authentication and Grant

JWT-Bearer (RFC 7523) lets a client or workload prove its identity using a
signed JWT instead of a shared secret. theauth-go v2.4 adds two related
features:

1. **JWT-Bearer client authentication:** substitute a signed JWT for
   `client_secret` in any token request.
2. **JWT-Bearer grant:** exchange an external JWT (e.g., a Kubernetes
   ServiceAccount token) for a theauth access token directly, without an
   interactive authorization code flow.

## The headline use case: Kubernetes workload identity

A Kubernetes Pod running in a namespace has a projected ServiceAccount token
automatically mounted at `/var/run/secrets/kubernetes.io/serviceaccount/token`.
This token is signed by the cluster's OIDC issuer. With JWT-Bearer:

```
Pod                        theauth-go AS              Target API
 |                              |                         |
 | POST /oauth/token            |                         |
 |  grant_type=jwt-bearer       |                         |
 |  assertion=<k8s SA token>    |                         |
 |----------------------------->|                         |
 |  Verify: issuer matches      |                         |
 |  TrustedJWTIssuer config     |                         |
 |  SubjectMapper: SA name ->   |                         |
 |  theauth client ID           |                         |
 |                              |                         |
 |  access_token (theauth JWT)  |                         |
 |<-----------------------------|                         |
 |                              |                         |
 | GET /api/resource            |                         |
 |  Authorization: Bearer <token>                         |
 |------------------------------------------------------->|
```

No secrets need to be distributed to the Pod. The Kubernetes OIDC issuer serves
as the root of trust.

## TrustedJWTIssuer and SubjectMapper

Configure one or more trusted external JWT issuers:

```go
cfg := theauth.Config{
    AuthorizationServer: &theauth.AuthorizationServerConfig{
        Issuer: "https://auth.example.com",
        JWTBearer: &theauth.JWTBearerConfig{
            TrustedIssuers: []theauth.TrustedJWTIssuer{
                {
                    // Issuer claim in the incoming JWT.
                    Issuer: "https://kubernetes.default.svc.cluster.local",
                    // JWKS URL to fetch the issuer's public keys.
                    JWKSU: "https://kubernetes.default.svc.cluster.local/openid/v1/jwks",
                    // SubjectMapper maps the JWT subject to a theauth client ID.
                    // Return ("", nil) to deny the request.
                    SubjectMapper: func(ctx context.Context, claims map[string]any) (string, error) {
                        sub, _ := claims["sub"].(string)
                        // sub looks like "system:serviceaccount:my-namespace:my-sa"
                        if strings.HasPrefix(sub, "system:serviceaccount:prod:") {
                            return "k8s-prod-workload", nil
                        }
                        return "", nil
                    },
                },
            },
        },
    },
}
```

The `SubjectMapper` receives the full claims map and returns the theauth
`client_id` that the assertion should authenticate as. Return an empty string
and a nil error to deny without error detail leakage. Return a non-nil error to
surface an `invalid_grant` error response.

## JWT-Bearer grant

```
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer
&assertion=<signed-jwt>
&scope=read:data
&resource=https://api.example.com
```

The AS:

1. Decodes the `assertion` JWT (no verification yet).
2. Looks up the `iss` claim in `TrustedIssuers`.
3. Fetches (or uses the cached) JWKS from `JWKSU` and verifies the signature.
4. Calls `SubjectMapper` to resolve a `client_id`.
5. Looks up the resolved client and applies its allowed scopes and resources.
6. Mints a theauth access token bound to the resolved `resource`.

The response follows the standard token response shape:

```json
{
  "access_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 900,
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token"
}
```

## JWT-Bearer client authentication

Instead of (or in addition to) the grant flow, a client can use a JWT to
authenticate on any grant type:

```
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
&client_id=my-client
&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
&client_assertion=<signed-jwt>
&scope=read:data
&resource=https://api.example.com
```

The JWT must be signed with the private key corresponding to the public key
registered for `my-client` (via `jwks_uri` or inline `jwks` on the client
registration). The AS verifies the signature, `iss == client_id`, `aud ==
AS issuer`, `exp`, `iat`, `nbf`, and a one-time `jti` (replay prevention
within the `AccessTokenTTL` window).

This replaces `client_secret` entirely. No shared secret needs to be
distributed or rotated.

## Combining with PAR + JAR (FAPI 2.0)

When JWT-Bearer client authentication is combined with PAR and JAR:

- The client pushes a signed authorization request to `/oauth/par` (JAR inside
  PAR).
- The client authenticates on the token endpoint using a JWT client assertion
  (JWT-Bearer client auth).
- PKCE S256 is enforced (default in theauth-go).

This combination meets the FAPI 2.0 Security Profile baseline. See
[PAR + JAR](par-jar.md) for the flow diagrams.

## Configuration reference

```go
type JWTBearerConfig struct {
    // TrustedIssuers lists external OIDC/JWT issuers that may be used
    // as the subject of a jwt-bearer grant assertion.
    TrustedIssuers []TrustedJWTIssuer
}

type TrustedJWTIssuer struct {
    // Issuer is the expected "iss" claim value.
    Issuer string
    // JWKSU is the JWKS endpoint URL for this issuer.
    JWKSU string
    // SubjectMapper maps claims to a theauth client_id.
    // Return ("", nil) to deny silently.
    SubjectMapper func(ctx context.Context, claims map[string]any) (string, error)
}
```

Set `AuthorizationServerConfig.JWTBearer` to enable; nil disables the feature.

## See also

- [PAR + JAR](par-jar.md)
- [CIBA backchannel authentication](ciba.md)
- [Configuration reference](../reference/configuration.md)
- RFC 7523: JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and
  Authorization Grants
