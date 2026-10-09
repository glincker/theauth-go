# Identity Assertion JWT Authorization Grant (ID-JAG)

Implements the flow in `draft-ietf-oauth-identity-assertion-authz-grant`: a client that already holds a user's identity at one authorization server (the IdP) trades it for a short lived assertion addressed to a second authorization server, then redeems that assertion there for an access token. The user is not sent through another consent page.

The draft is still moving. Names and checks here follow the version this was written against, so expect changes.

## Issuing (this server acts as the IdP)

```go
AuthorizationServer: &theauth.AuthorizationServerConfig{
    Issuer: "https://idp.example.com",
    IDJAG: &theauth.IDJAGConfig{
        Audiences: []string{"https://rs-as.example.com"}, // authorization servers you may address
        TTL:       5 * time.Minute,                       // default 5, at most 10
    },
}
```

The client calls the token endpoint with RFC 8693 token exchange:

```
POST /oauth/token
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&requested_token_type=urn:ietf:params:oauth:token-type:id-jag
&subject_token=<access token issued by this server to this client>
&subject_token_type=urn:ietf:params:oauth:token-type:access_token
&audience=https://rs-as.example.com
&resource=https://rs.example.com/api
&scope=read
```

The response has `issued_token_type` set to the id-jag URN, `token_type` `N_A`, and the assertion in `access_token`. It is a JWT with `typ` `oauth-id-jag+jwt` and the claims `iss`, `sub`, `aud`, `client_id`, `jti`, `iat`, `exp`, `scope` and `resource`.

Checks: the client authenticates; `audience` must be in `IDJAG.Audiences`; the subject token must be an unrevoked access token this server issued to that same client for a user (agent tokens are refused); a DPoP bound subject needs a matching proof; `scope` can only narrow the subject's scope; `exp` never outlives the subject token.

This server has no ID token issuance, so the subject is one of its own access tokens (JWT or opaque) rather than an ID token.

Turning `IDJAG` on also advertises the token exchange grant, and the token exchange path for ordinary agent delegation still needs `AgentIdentity`.

## Redeeming (this server acts as the second authorization server)

Redemption uses the existing jwt-bearer grant, so it needs `JWTBearer` with the issuing server listed as a trusted issuer (JWKS URL, allowed algorithms and a `SubjectMapper`), plus `IDJAG` set (the audiences list can be empty).

```
POST /oauth/token
grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer
&assertion=<id-jag>&resource=https://rs.example.com/api&scope=read
(+ client authentication)
```

An assertion whose header `typ` is `oauth-id-jag+jwt` gets extra checks on top of the normal ones (trusted issuer, signature, `aud` equals this issuer, freshness, `jti` replay):

- the client must authenticate, and the `client_id` claim must equal that client;
- `jti` is required;
- if the assertion has a `resource`, it must equal the request's `resource`;
- the granted scope is the assertion's `scope`, narrowed by the request, and must fit the resource's catalog.

Without `IDJAG` set, such an assertion is refused.

## Audit events

`id_jag.issued` on issue. Redemption emits the existing `jwt_bearer.token_minted`.
