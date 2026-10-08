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

Not yet pluggable: the client-auth Argon2id cache, the introspection cache and the `mcpresource` JWKS cache. They hold derived data, not security decisions.

## Pick an adapter

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

MySQL and SQLite use `sqlkv.MySQL` and `sqlkv.SQLite` with the `*sql.DB` you passed to the storage package. `sqlkv.Schema(dialect, table)` returns the DDL if you prefer your own migration tool. Expired rows are pruned on a fraction of writes; call `store.Prune(ctx)` from a timer if traffic is low. The limiter built by `kv.FromCache` is a fixed window, so a burst can reach twice the limit across a window boundary.

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

cfg.Stores = kv.FromCache(kvredis.New(goRedis{rdb}, "theauth:"))
```

Every operation is one Lua script, so it is atomic and takes one round trip.

You can mix: a Redis limiter with the default replay cache is just `kv.Stores{RateLimiter: ...}`.

## Your own backend

Implement any of the interfaces. `kvtest.Run(t, factory)` is a contract suite for `kv.Cache` implementations; the factory receives a fake clock to hand to your adapter.

## Behavior notes

- Rate-limit keys include a rule name and a per-middleware sequence number, so `RateLimitByIP(5)` on sign-in and `RateLimitByIP(5)` on sign-up keep separate budgets. Replicas share budgets when they mount routes in the same order, which is the normal case.
- A limiter backend error fails open for sign-in middleware (an outage should not lock users out) and for the OAuth endpoint limits. The device verification page fails closed.
- With a shared limiter you still need `TrustedProxies` set behind a load balancer, or every request shares the proxy's address.
