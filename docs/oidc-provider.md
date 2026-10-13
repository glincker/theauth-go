# OpenID Provider

With `AuthorizationServer.OIDC` set the authorization server is an OpenID Connect provider: it issues ID tokens, serves userinfo, supports RP-initiated logout and sends back-channel logout tokens. Without it the server behaves as before.

## What already existed

- `GET /.well-known/openid-configuration` (and the path-inserted form) served the RFC 8414 document.
- `nonce`, `max_age`, `acr_values`, `prompt` and the `auth_time`, `acr` and `amr` claims on access tokens.

New with `OIDC`: ID tokens, `userinfo_endpoint`, `end_session_endpoint`, back-channel logout, pairwise subjects, and the OpenID fields in the discovery document.

## Enable

```go
AuthorizationServer: &theauth.AuthorizationServerConfig{
    Issuer:    "https://auth.example.com",
    Resources: []theauth.ProtectedResource{{Identifier: "https://api.example.com", Scopes: []string{"read"}}},
    OIDC: &theauth.OIDCConfig{
        PairwiseSalt: []byte(os.Getenv("OIDC_PAIRWISE_SALT")), // 16+ bytes, optional
    },
}
```

| Field | Meaning |
|---|---|
| `IDTokenTTL` | ID token lifetime. Default `AccessTokenTTL`. |
| `PairwiseSalt` | Keys the pairwise subject HMAC. Needed for any pairwise client. Keep it stable: changing it changes every pairwise `sub`. |
| `DefaultSubjectType` | `public` (default) or `pairwise` for clients that do not choose. |
| `BackchannelLogoutTimeout` | Per delivery timeout. Default 5s. |
| `AllowPrivateNetworks`, `HTTPClient` | Let back-channel logout reach private hosts, or supply your own client. Development and tests only. |

`openid`, `profile` and `email` are accepted without being listed in a resource's `Scopes`.

## ID tokens

A token response carries `id_token` when the grant has the `openid` scope and a user. Claims: `iss`, `sub`, `aud` (the client id), `iat`, `exp`, `at_hash`, `nonce` (authorization code grant only), `auth_time`, `acr`, `amr` and `sid`. The signing algorithm follows the client's access token policy, so the same JWKS and rotation serve both. `at_hash` uses SHA-512 for EdDSA and SHA-256 otherwise. Refresh responses carry a fresh ID token with the same `sid` and no `nonce`.

## Userinfo

`GET` or `POST /oauth/userinfo` with `Authorization: Bearer <access token>` (or `DPoP`, with a proof, for bound tokens). The token needs the `openid` scope. `profile` adds `name`, `given_name`, `family_name`, `picture`, `updated_at`; `email` adds `email` and `email_verified`. Failures answer `401 invalid_token` or `403 insufficient_scope`.

## Pairwise subjects

Clients choose `subject_type` at registration: `public` or `pairwise`. A pairwise `sub` is `HMAC-SHA256(PairwiseSalt, sector || 0x00 || user id)`, base64url encoded. The sector is the host of the client's redirect URIs; a pairwise client must register redirect URIs on one host (there is no `sector_identifier_uri`). The same user gets the same `sub` for one sector and different values across sectors. Access tokens keep the local user id in `sub`; ID tokens, userinfo and logout tokens use the client's `sub`.

## Logout

Register three fields next to the usual client metadata (authenticated registration only):

| Field | Meaning |
|---|---|
| `post_logout_redirect_uris` | Exact match list for `post_logout_redirect_uri`. |
| `backchannel_logout_uri` | Receives `logout_token` by POST. `https` unless `AllowPrivateNetworks`; delivery goes through the SSRF guard. |
| `backchannel_logout_session_required` | Stored and echoed; logout tokens always carry `sid`. |

`GET` or `POST /oauth/end_session` accepts `id_token_hint`, `client_id`, `post_logout_redirect_uri` and `state`. The hint is checked against this server's keys (expired hints are fine) and must belong to the signed-in user. A redirect URI that is not registered is refused with `400` and the session is kept. On success the browser session is revoked, its cookie cleared, back-channel tokens go out, and the user is redirected (or shown a short signed-out page). There is no confirmation prompt.

Logout tokens are JWTs with `typ: logout+jwt`, claims `iss`, `aud`, `iat`, `exp` (2 minutes), `jti`, `sub`, `sid` and `events`, and no `nonce`. Deliveries run in the background and failures are only logged. To notify clients for a logout that does not pass through `end_session`, call `TheAuth.OIDCLogout(ctx, userID, sessionID)`; it does not revoke the session.

`sid` is derived per client from the session id, so two clients cannot correlate a user by it.

## Limits

- Session linkage (code to session, token family to session, session to clients) is kept in `Config.Stores.Cache`, not in the database. Use a shared cache (Redis or SQL) on more than one replica. A lost entry only drops `sid` and the back-channel notification for that grant. Linking is not atomic across concurrent first logins to different clients.
- Refresh tokens are not revoked at logout; revoke them yourself if you need that.
- Only the code flow exists, so there are no `response_type` values such as `id_token`, and no `claims` parameter or request-time `userinfo` signing.
- Client OIDC metadata is stored as one JSON column (`oidc_metadata`, migration `0025` for Postgres and MySQL). The SQLite module has no authorization server storage yet.
