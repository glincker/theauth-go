# CORS for the authorization server

Browser based MCP and OAuth clients cannot read discovery metadata or call the token endpoint
cross-origin unless the server answers with CORS headers. The authorization server sends none by
default. Set `AuthorizationServerConfig.CORS` to opt in. The zero value changes nothing: no headers,
no preflight routes.

```go
AuthorizationServer: &theauth.AuthorizationServerConfig{
    Issuer: "https://auth.example.com",
    CORS: theauth.CORSConfig{
        AllowedOrigins: []string{"https://app.example.com"},
        PublicOrigins:  []string{"*"}, // metadata and jwks only
        Discovery:      true,
        JWKS:           true,
        Token:          true,
        Register:       true,
    },
},
```

## Fields

| Field | Meaning |
| --- | --- |
| `AllowedOrigins` | Exact origins (scheme, host, optional port) allowed on every enabled group. |
| `PublicOrigins` | Overrides `AllowedOrigins` for `Discovery` and `JWKS`. The only list that may hold `*` next to enabled token endpoints. |
| `Discovery`, `JWKS`, `Register`, `Token`, `Introspect`, `Revoke`, `UserInfo` | Per group switches, all off by default. |
| `AllowCredentials` | Sends `Access-Control-Allow-Credentials: true` on the non public groups, for an exactly listed origin only. |
| `ExposedHeaders` | Headers scripts may read. Default `DPoP-Nonce` and `WWW-Authenticate`. |
| `MaxAge` | Preflight cache time. Zero means 10 minutes, negative omits the header. |

## Behavior

- Origins match exactly after lower-casing and dropping a trailing slash or default port.
  `https://App.Example.com/` and `https://app.example.com:443` are the same origin.
- An origin that is not listed never gets `Access-Control-Allow-Origin`. The server never reflects
  an arbitrary origin. `Origin: null` is never allowed.
- `Vary: Origin` is sent on every response of an enabled group, allowed or not.
- Preflight (`OPTIONS`) is answered with 204 before authentication and rate limiting.
  `Access-Control-Allow-Methods` lists only what the endpoint serves (`GET` for metadata and jwks,
  `POST` for register, token, introspect and revoke, `GET, POST` for userinfo).
  `Access-Control-Allow-Headers` is `Accept, Content-Type, Authorization, DPoP`.
- Error responses carry the same headers, so a script can read `DPoP-Nonce` from a `use_dpop_nonce`
  token error and retry.
- Groups: `Discovery` covers `/.well-known/oauth-authorization-server`, `/.well-known/openid-configuration`
  and `/.well-known/oauth-protected-resource` (with their path forms). `/oauth/authorize` and the
  device, CIBA and PAR endpoints are not CORS enabled because browsers reach them by navigation or
  from a server.

## Startup validation

`theauth.New` fails with a clear error when:

- `*` is listed in `AllowedOrigins` and any of `Register`, `Token`, `Introspect`, `Revoke` or
  `UserInfo` is on (`ErrCORSWildcardPrivate`). Use `PublicOrigins` for the wildcard.
- `AllowCredentials` is set together with `*` in either list (`ErrCORSWildcardCredentials`).
- An origin is not a plain `http` or `https` origin, including `null` and origins with a path
  (`ErrCORSInvalidOrigin`).

The security doctor reports `oauth.cors_loose` (low) for `*` on discovery together with credentials,
or for `Token` enabled with no exact origin. See [SECURITY-DOCTOR.md](SECURITY-DOCTOR.md).
