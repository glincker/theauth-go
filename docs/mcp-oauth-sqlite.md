# OAuth 2.1 for an MCP server on SQLite

This guide runs the theauth OAuth 2.1 authorization server on the SQLite store and protects an MCP endpoint with it. One binary, one database file, no other services. The code below comes from `storage/sqlite/oauth_e2e_test.go`, `storage/sqlite/oauth_mcpresource_test.go` and `storage/sqlite/oauth_pathprefix_test.go`, which run against a real SQLite file in CI.

You need `storage/sqlite` (a separate module), a 32 byte `EncryptionKey` and an HTTPS origin for the issuer.

## 1. Open the database

The store runs on a `*sql.DB` you own, so you own the pragmas too. Foreign keys must be on (`New` refuses a database with them off). Add a busy timeout, WAL mode and immediate transactions so concurrent token requests queue instead of failing with `database is locked`.

```go
db, err := sql.Open("sqlite",
	"file:auth.db?_pragma=foreign_keys(1)&_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)&_txlock=immediate")
if err != nil {
	log.Fatal(err)
}
if err := sqlitestore.Migrate(ctx, db); err != nil { // applies 0001 to 0034
	log.Fatal(err)
}
store, err := sqlitestore.New(db)
```

`Migrate` applies every pending file. If you manage the schema yourself, use `Migrations` or `RenderMigrations` and apply 0001 to 0016 plus 0020 to 0034 in order. The OAuth server tables are 0020 to 0029, agents and delegation grants are 0030 and 0031, the jwt-bearer `jti` cache is 0032, CIBA is 0033 and session auth methods are 0034. See [storage-capabilities.md](storage-capabilities.md) for the full list.

## 2. Configure the authorization server

```go
a, err := theauth.New(theauth.Config{
	Storage:       store,
	BaseURL:       "https://auth.example.com",
	EncryptionKey: key, // 32 bytes, seals the JWKS private keys
	AuthorizationServer: &theauth.AuthorizationServerConfig{
		Issuer: "https://auth.example.com",
		Resources: []theauth.ProtectedResource{{
			Identifier: "https://mcp.example.com/mcp",
			Scopes:     []string{"files.read", "files.write"},
		}},
		RegistrationTokens:    []string{initialAccessToken},
		AccessTokenRevocation: true,
		CIBA: &theauth.CIBAConfig{
			AuthenticationDevice: device,
		},
	},
	AgentIdentity: &theauth.AgentConfig{},
})
```

What each part does:

- **Issuer** becomes the `iss` claim and the base of every endpoint in the metadata document (`<issuer>/oauth/token`, `<issuer>/oauth/jwks`). A trailing slash is removed. It must be an https URL with no query or fragment.
- **Resources** lists the MCP endpoints this server issues tokens for. Every authorize and token request carries a `resource` parameter (RFC 8707) that must match one of them, and the token's `aud` is set from it. If your clients omit `resource`, see [client-compat.md](client-compat.md).
- **Signing keys** are generated for you. The server creates an Ed25519 key at startup, stores the private half in the `theauth_jwks_keys` table sealed with `EncryptionKey`, and rotates every 30 days (`KeyRotationPeriod`). Retired keys stay in `/oauth/jwks` for 90 days (`KeyRetention`). Keep `EncryptionKey` stable: a different key cannot unseal the stored ones.
- **PKCE** is always required and the method is S256. There is nothing to switch on. The metadata document advertises `code_challenge_methods_supported: ["S256"]`.
- **Dynamic client registration** (`POST /oauth/register`) is closed by default. Set `RegistrationTokens` to accept clients that present one of those bearer tokens, or `AllowAnonymousRegistration: true` to accept anyone (limited to 1 request per minute per IP). A native app client registers like this in the tests:

```go
code, out := e.register(oaJSON{
	"client_name":                "Claude Code (e2e)",
	"redirect_uris":              []string{"http://127.0.0.1:8976/callback"},
	"grant_types":                []string{"authorization_code", "refresh_token"},
	"response_types":             []string{"code"},
	"token_endpoint_auth_method": "none",
}, "")
```

A confidential client, such as the MCP server calling introspection, registers with the initial access token and `client_secret_basic`.

- **AccessTokenRevocation** turns on the jti denylist. SQLite supports it (migration 0023). Without it, revoked access tokens stay valid until they expire.
- **AgentIdentity** is optional. It adds agents, delegation grants and RFC 8693 token exchange (migrations 0030 and 0031).

`Config.AuthorizationServer.LoginURL` defaults to `/auth/login`. Unauthenticated authorize requests are sent there with a `next` parameter.

## 3. Mount under a path prefix

There are two different prefixes, and they do different things.

| Setting | What it moves |
| --- | --- |
| `Config.PathPrefix` (default `/auth`) | The `/auth/*` routes (sign-in, sessions, step-up, `/auth/me`). |
| The mount point you choose in your router | Everything, including `/oauth/*` and `/.well-known/*`. |

The OAuth server routes are registered at the root of the router that `Mount` or `Handler` returns. They do not move with `Config.PathPrefix`. To serve them under `/api/v1/auth-lib`, strip the prefix and set the issuer to include it:

```go
const prefix = "/api/v1/auth-lib"

AuthorizationServer: &theauth.AuthorizationServerConfig{
	Issuer: "https://app.example.com" + prefix,
	// ...
},

h := a.Handler() // build it once: each call mounts a fresh set of routes and rate-limit buckets
mux := http.NewServeMux()
mux.Handle(prefix+"/", http.StripPrefix(prefix, h))
```

With that mount, the endpoints in the metadata document line up with where the router serves them: `https://app.example.com/api/v1/auth-lib/oauth/token`, `/oauth/jwks`, `/oauth/authorize` and the rest.

### What the host must serve at the origin root

RFC 8414 and RFC 9728 put the well-known document at the origin root, with the issuer or resource path added after it. A client that is given `https://app.example.com/api/v1/auth-lib` as the issuer asks for:

```
https://app.example.com/.well-known/oauth-authorization-server/api/v1/auth-lib
https://app.example.com/.well-known/openid-configuration/api/v1/auth-lib
```

and for a resource at `https://app.example.com/api/mcp`:

```
https://app.example.com/.well-known/oauth-protected-resource/api/mcp
```

The `StripPrefix` mount above does not answer these, because they are not under `/api/v1/auth-lib/`. They return 404 until you forward the origin root `/.well-known/` path to the library as well:

```go
mux.Handle(prefix+"/", http.StripPrefix(prefix, h))
mux.Handle("/.well-known/", h) // no StripPrefix: the library matches the issuer path itself
```

The library accepts the path form when the suffix equals the issuer path (for authorization server metadata) or the path of a configured resource (for protected resource metadata). Any other suffix returns 404, so one origin never answers for an issuer it does not own. The plain forms without a suffix are also served, and return the same document.

`TestOAuthMetadataUnderPathPrefix` in `storage/sqlite/oauth_pathprefix_test.go` pins all of this: the endpoints under the prefix, the 404 from a host that mounts just the prefix, and the 200 once `/.well-known/` is forwarded. If the issuer has a path and you do not forward the well-known path, clients that follow the RFCs will not find your server. If a reverse proxy sits in front, route `/.well-known/oauth-authorization-server`, `/.well-known/openid-configuration` and `/.well-known/oauth-protected-resource` (with their suffixes) to the same backend.

Also see [mcp-metadata-paths.md](mcp-metadata-paths.md) for the URL forms.

## 4. Protect the MCP endpoint

`mcpresource` validates the bearer token on each MCP request. It is a separate zero dependency module, so it can run in a different process from the authorization server.

```go
v := mcpresource.New("https://mcp.example.com/mcp",
	mcpresource.WithJWKS("https://auth.example.com/oauth/jwks"),
	mcpresource.WithIntrospection("https://auth.example.com/oauth/introspect", rsID, rsSecret),
	mcpresource.WithCacheTTL(20*time.Millisecond),
)
mux.Handle("/mcp", v.Middleware(handler))
mux.Handle("/write", v.Middleware(v.RequireScope("files.write")(writeHandler)))
```

`WithCacheTTL` sets the JWKS and introspection cache window. A value of zero or less is ignored and the 60 second default stays. If neither `WithJWKS` nor `WithIntrospection` is set, every request gets a 401; `v.Diagnostics()` reports that as a `no-verification-source` warning. It also warns when `WithDeviceRevocationIntrospection` is set without an introspection URL.

On a missing or bad token the middleware answers 401 with a `WWW-Authenticate: Bearer` header that carries `resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp"`. A token for another audience is refused. A token without the scope gets 403 `insufficient_scope` with the scope named in the header. Inside the handler, `v.Principal(ctx)` returns the subject, scopes, audience and, for delegated agent tokens, the actor and actor chain.

### Opaque access tokens

A client registered with `access_token_format: "opaque"` (needs `TokenPolicy` on the AS) gets random reference tokens instead of JWTs. The resource server cannot verify those offline, so turn on `WithOpaqueTokens` next to `WithIntrospection`:

```go
v := mcpresource.New("https://mcp.example.com/mcp",
	mcpresource.WithJWKS("https://auth.example.com/oauth/jwks"), // optional if you only see opaque tokens
	mcpresource.WithIntrospection("https://auth.example.com/oauth/introspect", rsID, rsSecret),
	mcpresource.WithOpaqueTokens(),
)
```

A token that has three base64url segments and a header starting `eyJ` is a JWT and always takes the JWT path. A bad JWT is never retried as an opaque token. Anything else is sent to `/oauth/introspect`, unless it is longer than 2048 bytes or has characters outside the RFC 6750 token set; those get a 401 without calling the AS.

The Principal comes from the introspection response, and the checks match the JWT ones:

- `active` must be true. Inactive gives 401 `invalid_token`.
- `aud` must contain the resource URI. A response with no `aud` is refused.
- `exp` must be present and not past (with the usual clock skew). No `exp` is refused.
- A `token_type` of `refresh_token` is refused, since the AS reports active refresh tokens too.
- Scope may be empty, as it may for a JWT.
- `act`, `delegation_grant_id`, `device_id`, `acr`, `amr`, `auth_time` and `authorization_details` fill the matching Principal fields.

DPoP works through `cnf.jkt` in the response. If it is present, the request must carry a matching proof and `WithDPoPVerification` must be set, exactly as for a bound JWT. A response that says `token_type: "DPoP"` without `cnf.jkt` is refused.

Answers are cached under a SHA-256 of the token, never the token. The entry lives for `WithCacheTTL`, or for the AS `Cache-Control` max-age when that is a positive number of seconds (a `max-age=0` falls back to `WithCacheTTL`). The cache holds at most 10000 entries. A token revoked at `/oauth/revoke` is therefore still accepted until its cached answer expires; lower `WithCacheTTL` and the AS `IntrospectionCacheTTL` to shrink that window.

Without `WithIntrospection`, every opaque token is refused and `v.Diagnostics()` reports `opaque-no-introspection`.

### Revocation is not seen by offline validation

With `WithJWKS` alone the middleware checks the signature, audience and expiry offline. A token that was revoked at `/oauth/revoke` still passes until it expires. The e2e test pins this on purpose: after a revoke, the validator with just a JWKS keeps answering 200.

To see revocation, add a revocation checker that asks the server:

```go
mcpresource.WithRevocationChecker(
	mcpresource.RevocationCheckerFunc(func(_ context.Context, token string, _ *mcpresource.Principal) (bool, error) {
		return !active(e.introspect(rsID, rsSecret, token)), nil
	}))
```

A checker that reports a token revoked produces 401 `invalid_token`. If the checker returns an error the request is refused too, unless you add `WithRevocationFailOpen()`. The checker runs on every request, so keep it fast or cache it. `WithDeviceRevocationIntrospection()` is a shorthand that introspects the tokens issued to devices and passes the rest.

The middleware calls the introspection endpoint for tokens that carry an `act` claim or a `delegation_grant_id` (agent tokens from token exchange), or when a revocation checker you wrote does. A plain user token is never introspected by the middleware itself. In the test, revoking the delegation grant turns the agent's token into a 401 once the introspection cache window passes. The resource server honors the `Cache-Control: max-age` the server sends on introspection responses (`IntrospectionCacheTTL`, 60 seconds by default) over its own `WithCacheTTL`, so that is how long a revocation can take to show. On the server side, `SubjectActiveCacheTTL` bounds how long an agent or user is treated as still active.

## 5. Consent

By default the server approves an authenticated authorize request and issues a code for every scope asked for. Set `ConsentHandler` to show your own consent screen, narrow the scopes and set an expiry:

```go
ConsentHandler: func(ctx context.Context, r theauth.ConsentRequest) (theauth.ConsentDecision, error) {
	return theauth.ConsentDecision{Action: theauth.ConsentInteract, RedirectToConsentURL: "/consent"}, nil
},
```

Your page finishes with `TheAuth.CompleteConsent`. Tickets are single use and are recorded in the replay cache (`Config.Stores.ReplayCache`), which is in memory unless you plug in a shared one. With more than one process, see [pluggable-stores.md](pluggable-stores.md); the `kv/sqlkv` adapter runs on the same SQLite file. Full details, including CSRF handling for your consent endpoint, are in [oauth-consent.md](oauth-consent.md).

## 6. Step up with session auth methods

The `amr`, `acr` and `auth_time` claims come from the session's recorded sign-in methods, which SQLite stores in migration 0034. An MCP server that needs a stronger factor asks for it with `acr_values` (for example `urn:theauth:acr:mfa`) or `max_age` on the authorize request. A session that used just a password is sent back to the login URL with `reauth=1` and the hints, completes `POST /auth/step-up`, and returns with the stronger record. See [session-auth-methods.md](session-auth-methods.md).

If a database has not run 0034 yet, sessions still read and write without an auth record, and recording one reports `ErrStorageMissingCapability`. The tokens then fall back to `amr: ["pwd"]`. Apply the migration to turn the full behavior on.

## 7. Agents and policies

Agents can mint their own tokens and act for a user through delegation grants. To restrict what an agent token may carry, attach an IAM style policy through `AgentConfig.PolicyEngine`. A deny fails the mint with `access_denied`, and the policy ids are recorded in the token and the audit log. See [agent-policies.md](agent-policies.md) and, to trim unused grants, [policy-shrink.md](policy-shrink.md).

## 8. CIBA

With `CIBA` configured, the server mounts `POST /oauth/bc-authorize`. Your `AuthenticationDevice.Notify` is called with the request, you show the prompt, and you call `ApproveBackchannelAuth` (or `DenyBackchannelAuth`) with the user id. The client polls `/oauth/token` with `urn:openid:params:grant-type:ciba`:

```go
if err := e.a.ApproveBackchannelAuth(ctx, reqID, user.ID); err != nil {
	t.Fatalf("ApproveBackchannelAuth: %v", err)
}
```

Before approval the poll returns `authorization_pending`. After approval a successful poll returns tokens and marks the request consumed, so a second poll gets `invalid_grant`. On SQLite the approve, deny and redeem steps are single conditional statements, so exactly one caller wins.

## 9. Restart durability

Everything the server needs lives in the database file: clients, signing keys, unredeemed authorization codes, refresh tokens, the revocation list and CIBA requests. The restart test stops the server, reopens the same file with the same `EncryptionKey` and checks that:

- the JWKS key ids are unchanged,
- an access token issued before the restart still verifies and introspects as active,
- a token revoked before the restart is still inactive,
- a refresh token issued before the restart still rotates,
- an authorization code issued but not redeemed before the restart redeems once, and a second try gets `invalid_grant`.

Two things are not durable unless you arrange it. The default rate limiter, replay cache and CIMD cache are in process memory ([pluggable-stores.md](pluggable-stores.md)), and the audit writer is asynchronous, so call `a.Close()` on shutdown to let it drain (up to `Audit.DrainTimeout`).

## Operating notes

- SQLite allows one writer at a time. WAL mode lets readers continue while a write is in progress, and the busy timeout makes writers wait. A single process per database file is the supported shape; for several replicas use Postgres or MySQL.
- Back up the database file together with `EncryptionKey`. The file alone cannot sign tokens.
- Call `SweepExpired` from a ticker to remove expired rows.
