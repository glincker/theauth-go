# theauth-go v2.7.1

Docs: https://docs.theauth.dev/go . Full list: [CHANGELOG.md](../CHANGELOG.md).

This is a security fix. If you use the authorization server with `private_key_jwt` client authentication or trusted JWT issuers, upgrade.

```bash
go get github.com/glincker/theauth-go/v2@v2.7.1
```

## Upgrade notes

- **JWKS URLs must use `https`.** Plain `http` is refused unless `JWTBearerConfig.AllowPrivateJWKSNetworks` is set.
- **JWKS hosts that resolve to loopback, private, link-local, CGNAT or cloud metadata addresses are refused.** Local development and tests that serve a JWKS from `localhost` need `AllowPrivateJWKSNetworks: true`, or an injected `JWKSHTTPClient`.
- **Redirects are not followed.** A JWKS URL must serve the document directly.
- **Rotated keys are picked up after the cache TTL** (`JWKSCacheTTL`, default 5 minutes).
- **CIMD fetch errors now start with `safehttp:` instead of `cimd:`.** `errors.Is` still works.

## What was wrong

The server fetched a client's `jwks_uri` or a trusted issuer's `JWKSURL` with a plain HTTP GET: no address check, no timeout, redirects followed, and a cache that never expired. A client that registered a `jwks_uri` pointing at an internal address could make the server connect there.

## What changed

JWKS fetching now uses a guarded client (shared with CIMD in `internal/safehttp`). The address check runs at dial time, so DNS rebinding does not get around it. No proxy is used, requests time out after 5 seconds by default, the response must be status 200 and at most 512 KiB, and the cache expires entries after a TTL, holds at most 256 URLs by default, and never stores failed fetches. See [PR #213](https://github.com/glincker/theauth-go/pull/213).

## New options on `JWTBearerConfig`

| Option | Default | Purpose |
|---|---|---|
| `AllowPrivateJWKSNetworks` | `false` | Local development only. Permits private addresses and plain `http`. |
| `JWKSCacheTTL` | 5 minutes | How long a fetched JWKS is reused. |
| `JWKSCacheMaxEntries` | 256 | Maximum number of cached JWKS URLs. |
| `JWKSFetchTimeout` | 5 seconds | Total time allowed for one fetch. |
| `JWKSHTTPClient` | guarded client | Replaces the default client. It is used as is, so it must give equivalent protection. |
