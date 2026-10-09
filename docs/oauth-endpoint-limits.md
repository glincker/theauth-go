# OAuth endpoint abuse controls

`/oauth/token`, `/oauth/revoke`, `/oauth/introspect`, `/oauth/par`, `/oauth/bc-authorize` and `/oauth/device_authorization` are rate limited and protected from secret-verification floods. This is on by default when `Config.AuthorizationServer` is set.

```go
AuthorizationServer: &theauth.AuthorizationServerConfig{
    RateLimits: &theauth.ASRateLimits{
        PerIPPerMinute:                   120, // shared across the endpoints above
        PerClientPerMinute:               300, // secret-bearing requests only
        MaxConcurrentSecretVerifications: 8,   // Argon2id verifications at once
        SecretVerifyWait:                 2 * time.Second,
    },
}
```

A zero field takes the default shown. A negative value turns that control off.

- **Per IP.** One budget per client address. Over the limit you get `429` with `Retry-After` and `error=rate_limited`.
- **Per client.** Counted only when the request presents a `client_id` together with a secret or assertion. Public-client requests are not counted, so nobody can lock a public client out by naming it. An attacker who knows a confidential client's id can still use up that client's budget; the per-IP limit and the concurrency cap are the answer to that, and 300 per minute is high enough that normal clients never notice.
- **Concurrency cap.** Each Argon2id verification allocates 64 MiB. At most `MaxConcurrentSecretVerifications` run at once. A request that cannot get a slot within `SecretVerifyWait` receives `503` with `error=temporarily_unavailable`. Successful verifications are cached, so steady traffic from real clients rarely reaches Argon2id.

Counters live in `Config.Stores.RateLimiter` (see [pluggable-stores.md](pluggable-stores.md)). The concurrency cap is per process, since it protects local CPU and memory.

## Client address and X-Forwarded-For

The client address comes from the connection unless the peer is in `Config.TrustedProxies`. For a trusted peer, `X-Forwarded-For` is read from the right: entries that are themselves trusted proxies are skipped, and the first other address is the client. Anything to the left of it was supplied by the client and is ignored. An unparseable entry stops the walk and falls back to the peer address. Multiple header lines count as one list.

This changes behavior for deployments that list a proxy in `TrustedProxies`: previously the leftmost entry was used, which a client could forge to dodge per-IP limits. If your proxy chain has more than one hop, list every hop's CIDR in `TrustedProxies`.
