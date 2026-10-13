# Request admission

`Admission` is net/http middleware that runs before authentication. It refuses an anonymous flood cheaply and blocks cross-site writes against cookie sessions. It matches `guard.admit` in the TypeScript library.

```go
a, _ := theauth.New(theauth.Config{
    BaseURL: "https://app.example.com",
    Stores:  kv.FromCache(redisCache), // shared counters across replicas
    Admission: &theauth.AdmissionOptions{
        TrustedOrigins: []string{"https://admin.example.com"},
    },
})
http.ListenAndServe(":8080", a.Handler())
```

Setting `Config.Admission` applies it to every route `Mount` and `Handler` register. To guard your own routes, call `a.Admission(opts)` and wrap them.

## Rate limit tiers

| Tier | Routes | Default |
| --- | --- | --- |
| strict | `/oauth/token`, `/oauth/register`, `/oauth/par`, `/oauth/revoke`, `/oauth/introspect`, `/oauth/device_authorization`, `/oauth/bc-authorize`, `/authorize`, `/mcp/token`, `/mcp/register`, `/mcp/authorize` | 30 per 60s |
| mutation | other POST, PUT, PATCH, DELETE | 120 per 60s |
| read | GET, HEAD, OPTIONS | 300 per 60s |

Strict paths match case-insensitively as an exact path, a path prefix followed by `/`, or a suffix, so a mount prefix such as `/v1/auth` does not matter. Override with `AdmissionOptions.Limits` (a zero field keeps the default).

Over the limit the response is `429` with `Retry-After` (whole seconds, at least 1) and the body `{"code":"RATE_LIMITED","message":"Too many requests"}`. `Config.ErrorResponder` is honored.

## Bucket key

Client IP (from the connection, or `X-Forwarded-For` only for peers in `Config.TrustedProxies`), then a SHA-256 digest of the `Authorization` or `Cookie` header, then `unknown`. Raw credentials never reach the counter store. `Key` replaces the default; return `""` to fall back. `Skip` leaves a request out of rate limiting (the cross-site check still applies). `DisableRateLimit` turns the limits off.

## Counters

Counters use `Config.Stores.RateLimiter` (see [pluggable-stores.md](pluggable-stores.md)), so replicas share budgets. Without it each process counts alone in memory. The limiter is a fixed window. A store error lets the request through, so a counter outage never takes sign-in down.

## Cross-site check

Applies to POST, PUT, PATCH and DELETE that carry a cookie and no bearer `Authorization`. Allowed when `Sec-Fetch-Site` is `same-origin` or `none`, or when `Origin` (or `Referer`) is the request's own origin, `Config.BaseURL`, `Config.TrustedOrigins` or `AdmissionOptions.TrustedOrigins`. With no `Origin`, `Sec-Fetch-Site: cross-site` or `same-site` is refused. Refusal is `403` with `{"code":"CSRF_REJECTED",...}`. Set `DisableCSRF` to turn it off.

The built-in Origin check on `Mount` (code `csrf_origin_rejected`, `Config.DisableCSRFProtection`) stays in place and is independent. When both are on, admission runs first.

## Client SDKs

The codes match the TypeScript library, so `IsRateLimited` and `IsCSRFRejected` in the Go client SDK work against either server.

## Limits

- The window is fixed, so a burst can reach twice the limit across a boundary.
- Behind a proxy that rewrites `Host`, list the public origin in `TrustedOrigins` or `Config.BaseURL`.
