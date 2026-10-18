# Pluggable shared state

Out of the box, theauth keeps rate-limit counters, DPoP proof replay records and the CIMD document cache in process memory. With one replica that is fine. With several, each replica enforces its own limits and a DPoP proof replayed against another replica is accepted.

`Config.Stores` fixes that. It takes three small interfaces from the `kv` package. Leave a field nil and you get the in-memory default for that piece.

```go
type Stores struct {
    RateLimiter kv.RateLimiter // Allow(ctx, key, limit, window) (Decision, error)
    ReplayCache kv.ReplayCache // Seen(ctx, key, ttl) (already bool, error)
    Cache       kv.Cache       // Get, Set, SetNX, Delete, Incr with TTLs
}
```

Used by:

- `RateLimitByIP`, `RateLimitByEmail` and the OAuth endpoint limits (`RateLimiter`)
- DPoP proof `jti` replay protection (`ReplayCache`). A backend error rejects the proof.
- the CIMD document cache (`Cache`). Documents read from the shared tier are validated again.
- the SAML AuthnRequest tracker and assertion replay record (`Cache`). See [SAML with several replicas](#saml-with-several-replicas).

Not yet pluggable: the client-auth Argon2id cache, the introspection cache and the `mcpresource` JWKS cache. They hold derived data, not security decisions.

## Pick an adapter

> **Upgrading from an earlier release?** Redis and SQL keys now carry the
> `theauth:` prefix by default. Keys written before the upgrade are not read
> again under their old names. Read [Key prefix](#key-prefix) before you deploy.

Memory (default, one process):

```go
cfg.Stores = kv.NewMemory().Stores()
```

SQL, using the database you already run. Postgres through pgx:

```go
db := stdlib.OpenDBFromPool(pool) // github.com/jackc/pgx/v5/stdlib
store, _ := sqlkv.New(db, sqlkv.Postgres)
_ = store.EnsureSchema(ctx) // one table, theauth_kv; safe to repeat
cfg.Stores = kv.FromCache(store)
```

MySQL and SQLite use `sqlkv.MySQL` and `sqlkv.SQLite` with the `*sql.DB` you passed to the storage package. `sqlkv.Schema(dialect, table)` returns the DDL if you prefer your own migration tool. Expired rows are pruned on a fraction of writes; call `store.Prune(ctx)` from a timer if traffic is low. Prune only removes expired rows under this store's key prefix. The limiter built by `kv.FromCache` is a fixed window, so a burst can reach twice the limit across a window boundary.

Redis, without a driver dependency. `kv/redis` needs one method from your client:

```go
type goRedis struct{ c redis.Scripter } // github.com/redis/go-redis/v9

func (g goRedis) Eval(ctx context.Context, script string, keys []string, args ...any) (any, error) {
    v, err := g.c.Eval(ctx, script, keys, args...).Result()
    if errors.Is(err, redis.Nil) {
        return nil, nil
    }
    return v, err
}

cfg.Stores = kv.FromCache(kvredis.New(goRedis{rdb}))
```

Every operation is one Lua script, so it is atomic and takes one round trip.

You can mix: a Redis limiter with the default replay cache is just `kv.Stores{RateLimiter: ...}`.

## Key prefix

Redis and SQL stores prepend a prefix to every key. The default is `theauth:`, so several apps or features can share one Redis or one table without colliding or reading each other's keys.

```go
kvredis.New(goRedis{rdb})                              // keys: theauth:<key>
kvredis.New(goRedis{rdb}, kvredis.WithPrefix("billing:")) // keys: billing:<key>
kvredis.New(goRedis{rdb}, kvredis.WithoutPrefix())     // keys: <key>, as in earlier releases

sqlkv.New(db, sqlkv.Postgres)                          // rows: theauth:<key>
sqlkv.New(db, sqlkv.Postgres, sqlkv.WithoutPrefix())   // rows: <key>, as in earlier releases
```

`WithPrefix("")` is the same as `WithoutPrefix()`. The opt-out is an explicit call, so an empty value never turns the default off by accident.

### What changes on upgrade

**Stored key names change for every Redis and SQL user who does not opt out.** Entries written by the earlier release have unprefixed names, and the new code reads and writes `theauth:<key>` only. Concretely:

- Rate-limit counters restart at zero after the upgrade, so a client that was throttled can make requests again right away.
- DPoP `jti` replay records restart empty. A proof seen just before the upgrade can be replayed once after it, until its proof lifetime ends.
- Redis entries keep their TTL and expire on their own. Entries written without a TTL stay until you delete them.
- SQL rows keep their expiry, but `Prune` no longer matches them, so they stay in the table. A table used only by theauth can be cleaned once with `DELETE FROM theauth_kv WHERE k NOT LIKE 'theauth:%';`. Do not run that on a table another application shares, because it deletes that application's rows.

### Keep the old keys

To keep the names the earlier release used, so that limits and replay records carry over, use the opt-out on every replica:

```go
kvredis.New(goRedis{rdb}, kvredis.WithoutPrefix())
sqlkv.New(db, sqlkv.Postgres, sqlkv.WithoutPrefix())
```

During a rolling deploy, set the opt-out on the new replicas too, so old and new replicas read and write the same keys. Removing the opt-out later switches to prefixed keys, which resets counters and replay records once more.

### Scope

- Redis: the adapter sends no `KEYS`, `SCAN` or `FLUSH`. Each command addresses one key, with the prefix applied, so it cannot touch a key outside its prefix.
- SQL: `Prune` deletes only expired rows whose key starts with this store's prefix. Rows under other prefixes, including another app on the same table, are not touched.

## Your own backend

Implement any of the interfaces. `kvtest.Run(t, factory)` is a contract suite for `kv.Cache` implementations; the factory receives a fake clock to hand to your adapter. `kvtest.RunNamespaces(t, pairFactory)` checks that two stores sharing one backend (for example two prefixes on one table) do not see, delete or count each other's keys.

## Behavior notes

- Rate-limit keys include a rule name and a per-middleware sequence number, so `RateLimitByIP(5)` on sign-in and `RateLimitByIP(5)` on sign-up keep separate budgets. Replicas share budgets when they mount routes in the same order, which is the normal case.
- A limiter backend error fails open for sign-in middleware (an outage should not lock users out) and for the OAuth endpoint limits. The device verification page fails closed.
- With a shared limiter you still need `TrustedProxies` set behind a load balancer, or every request shares the proxy's address.

## SAML with several replicas

SP-initiated SAML login issues an AuthnRequest on one request and receives the response on another. The service records each request id so a response is accepted only when its `InResponseTo` names a request this SP issued for that connection, and only once. It also records every accepted assertion id, so a captured response cannot be replayed.

By default both records live in process memory. With one replica that is correct. With several, a response that lands on a replica that did not issue the request is rejected (login fails), and a replayed response is only caught by the replica that saw the original.

Set `Config.Stores.Cache` (the same setting used by the rest of this page) and SAML uses it automatically. There is no separate SAML option.

```go
cfg.Stores = kv.FromCache(store) // SQL or Redis adapter from above
```

What is stored, under the `saml:authn:` and `saml:assert:` prefixes:

- the request id and assertion id as SHA-256 digests, never the raw id or the SAML document
- the connection id and a digest of the relay state, so an id issued for one connection cannot satisfy another
- a one-time "used" marker written with `SetNX`, so of N concurrent responses exactly one wins
- TTLs: the request record lives for `SAMLConfig.AuthnRequestTTL` (default 10 minutes); assertion ids live until the assertion's `NotOnOrAfter` plus clock skew (between 1 minute and 1 hour)

A cache error fails the login closed. IdP-initiated logins (no `InResponseTo`) are still allowed, and their assertion id is one-time too. Some IdPs put a non-empty `InResponseTo` on IdP-initiated responses; those are rejected because no matching request exists.

`theauth doctor` reports `saml.tracker_in_memory` (low) when SAML is enabled and `Stores.Cache` is nil. Ignore it on a single instance.
