# MQTT broker authentication and authorization

The `iot/mqttauth` package answers the two questions an MQTT broker asks over HTTP: may this client connect, and may it publish to or subscribe to this topic. It speaks the EMQX 5 HTTP authenticator and authorizer contracts and, behind a flag, the mosquitto-go-auth HTTP backend contract. HiveMQ is covered by the same endpoints through its HTTP extension or a small extension that calls them.

Devices are principals from a `DeviceStore`. The package ships a memory store, a `database/sql` store for SQLite and PostgreSQL, and `IdentityStore`, which reads the device registry of the authorization server (see [Devices from the registry](#devices-from-the-registry)). It does not issue credentials: tokens come from [device tokens](device-tokens.md) or your own provisioning, and the broker only asks.

## Run it

```go
store := mqttauth.NewMemoryStore()
_ = store.PutDevice(ctx, mqttauth.Device{
    ID:          "boiler-7",
    OrgID:       "plant-1",
    Status:      mqttauth.StatusActive,
    TokenHashes: []string{mqttauth.HashToken(deviceToken)},
    Rules: []mqttauth.Rule{
        {Effect: mqttauth.Allow, Action: mqttauth.ActionPublish, Filter: "devices/{device_id}/telemetry/#"},
        {Effect: mqttauth.Allow, Action: mqttauth.ActionSubscribe, Filter: "devices/{device_id}/cmd/+"},
    },
})

h, err := mqttauth.New(mqttauth.Config{
    Store:        store,
    BrokerSecret: os.Getenv("MQTT_AUTH_BROKER_SECRET"),
    PurgeSecret:  os.Getenv("MQTT_AUTH_PURGE_SECRET"),
    Audit:        mqttauth.SlogSink(slog.Default()),
})
if err != nil { /* ... */ }
mux.Handle("/mqtt/", http.StripPrefix("/mqtt", h))
```

A complete program on SQLite is in `examples/mqtt-auth`. `New` fails when `BrokerSecret` is empty, because certificate fingerprints and the `device_id` attribute are only as trustworthy as the caller. Set `AllowUnauthenticatedBroker` only when the network already restricts who can reach the endpoint.

## Routes

| Route | Purpose |
| --- | --- |
| `POST /authn` | EMQX authenticator |
| `POST /authz` | EMQX authorizer |
| `POST /purge` | drop cached state for `{"device_id":"..."}` or `{"all":true}`, needs `PurgeSecret` |
| `POST /mosquitto/user`, `/superuser`, `/acl` | mosquitto-go-auth, only with `Config.Mosquitto` |

The broker sends `Authorization: Bearer <BrokerSecret>`. `Handler.MetricsHandler()` serves Prometheus text counters (`theauth_mqtt_authn_total`, `theauth_mqtt_authz_total`, `theauth_mqtt_cache_hits_total`, `theauth_mqtt_errors_total`) without a client library.

## EMQX setup

Authenticator (Dashboard or `emqx.conf`):

```hocon
authentication = [{
  mechanism = password_based
  backend = http
  method = post
  url = "https://auth.example.com/mqtt/authn"
  headers { "content-type" = "application/json", authorization = "Bearer ${MQTT_AUTH_BROKER_SECRET}" }
  body { username = "${username}", password = "${password}", clientid = "${clientid}", peerhost = "${peerhost}" }
}]

authorization {
  no_match = deny
  sources = [{
    type = http
    method = post
    url = "https://auth.example.com/mqtt/authz"
    headers { "content-type" = "application/json", authorization = "Bearer ${MQTT_AUTH_BROKER_SECRET}" }
    body { device_id = "${client_attrs.device_id}", username = "${username}", clientid = "${clientid}",
           action = "${action}", topic = "${topic}", peerhost = "${peerhost}" }
  }]
}
```

Set `authorization.no_match = deny`. EMQX treats any 4xx or 5xx answer from an HTTP source as "ignore" and falls through to `no_match`, which defaults to allow. For that reason this handler never answers a decision with an error status: every deny, including a wrong broker secret, a malformed body and a store outage, is `200 {"result":"deny"}`.

Verified against EMQX 5.8.6 (`emqx/emqx:5.8.6`, a real MQTT 3.1.1 client from the Eclipse Paho Go client 1.5.1 and `mosquitto_pub` and `mosquitto_sub` 2.1.2), with the configuration above reached over plain HTTP:

- A wrong token, a revoked device, an unknown device, an empty password, and a client ID that is another device's ID or unrelated to the device all end in a refused CONNECT. A client ID of the form `<id>-1` connects.
- The authorizer receives `device_id` from `client_attrs.device_id` as the template says. Publish is allowed on `devices/<id>/telemetry/#` and nowhere else. For a denied publish EMQX answers the MQTT 3.1.1 client normally and drops the message, so only a subscriber shows the difference.
- Subscribe filters behave as the topic rules section says: `devices/<id>/cmd/+` is granted, `devices/<id>/cmd/#`, `alerts/#`, `#`, `+/+`, another device's filter and `$SYS/#` get SUBACK 0x80. A rule that names `$SYS/broker/uptime` grants that one topic.
- Shared subscriptions: EMQX strips `$share/<group>/` and sends the bare filter to `/authz`, so `$share/g1/alerts/+` is granted and `$share/g1/secret/x` and `$share/g1/#` are refused with 0x80.
- `expire_at` works: a device with `ExpiresAt` 12 seconds after the handler started was disconnected by EMQX 10.4 seconds after it connected.
- When the handler is unreachable, a new connect is refused. An already connected client that publishes gets no delivery with `no_match = deny`, and gets delivery with `no_match = allow`, so the `no_match` setting above is not optional. This was tested with the handler process stopped, not with an HTTP 4xx or 5xx answer.

EMQX also keeps its own authorization cache, which is enabled by default (`authorization.cache`, TTL 1 minute, 32 entries per client). It sits in front of the handler, so neither `CacheTTL` nor `POST /purge` can shorten it. With it enabled at a 10 second TTL and the handler cache off, a revoked device kept publishing for 9.2 seconds after the revoke, with or without a purge. The configuration above sets `cache { enable = false }`; leave the broker cache off, or accept its TTL as the revocation latency.

`/authn` returns `client_attrs.device_id`, `client_attrs.org_id` and `client_attrs.method`, and `expire_at` when the credential or device expires (EMQX 5.8 or later disconnects the client then). The authorizer template above relays `client_attrs.device_id` (EMQX 5.7 or later), so the authorization check uses the identity that authentication established. Without it the handler falls back to `username` as the device ID and requires the client ID to be bound to it.

## Credentials

Checked in this order, with no fallback between kinds:

1. **Client certificate.** The TLS terminator (the broker or a proxy) verifies the chain and passes the SHA-256 fingerprint of the leaf certificate in the `X-Client-Cert-Fingerprint` header (name set by `CertFingerprintHeader`) or the `cert_fingerprint` body field. Hex, colon separated hex and a `sha256:` prefix are accepted. Two values that disagree, or a value that is not a SHA-256 digest, deny. The fingerprint must be in `Device.CertFingerprints`.
2. **JWT as password.** Enabled by `Config.JWT`. A password with three dot separated parts starting with `eyJ` is verified with your `Keyfunc` (for example the JWKS of your theAuth issuer). The algorithm list, issuer, audience and `exp` are required (RFC 7519, RFC 8725 section 3.1). The `sub` claim maps to `Device.Subject`, then to `Device.ID`.
3. **Username and opaque token.** Username is the device ID, password a token whose `HashToken` digest is in `Device.TokenHashes`. The comparison is constant time and an unknown device costs the same hash.

Unless `AllowAnyClientID` is set, the MQTT client ID must equal the device ID or start with `<id>-`. Otherwise one authenticated device could connect with another's client ID and take over its session.

Only `active` devices authenticate. `ExpiresAt` is honored on every path.

## Topic rules

A `Rule` has an effect (`allow` or `deny`), an action (`publish`, `subscribe` or `all`) and a topic filter. `{device_id}` and `{org_id}` in a filter are replaced with the authenticated device's values. Device and org IDs may not contain `/`, `+`, `#`, `$`, braces or whitespace, so an ID cannot widen a filter.

Matching follows MQTT 5.0 section 4.7:

- Publish: the topic name must contain no wildcard and must match an allow rule's filter. `sport/#` matches `sport`.
- Subscribe: an allow rule must cover the whole requested filter. `devices/x/cmd/+` does not allow `devices/x/cmd/#`, and `#` is allowed only by a rule on `#`.
- Deny wins. For a subscription any overlap with a deny rule's filter denies, so subscribing to `#` cannot get around a deny on `secret/#`.
- Filters starting with a wildcard never match topics starting with `$` (section 4.7.2). `$SYS/#` needs a rule that names `$SYS`. Publishing to `$SYS/` is always denied.
- Shared subscriptions `$share/<group>/<filter>` (section 4.8.2) are checked as `<filter>`. A malformed share prefix denies.

Rules are validated when stored: unknown placeholders, `#` before the last level and `$share/` inside a rule are rejected.

## Devices from the registry

Devices enrolled through [device tokens](device-tokens.md) live in the storage that implements `theauth.DeviceIdentityStorage`. `IdentityStore` serves the broker from them, read only:

```go
var purge mqttauth.Purger

a, err := theauth.New(theauth.Config{
    Storage: store,
    AuthorizationServer: &theauth.AuthorizationServerConfig{
        // ...
        DeviceTokens: &theauth.DeviceTokensConfig{OnRevoke: purge.OnRevoke},
    },
})
// ...
h, err := mqttauth.New(mqttauth.Config{
    Store:        mqttauth.NewIdentityStore(store),
    BrokerSecret: os.Getenv("MQTT_AUTH_BROKER_SECRET"),
    Audit:        mqttauth.TheAuthSink(a),
    JWT:          &mqttauth.JWTConfig{ /* your issuer JWKS, audience, methods */ },
})
purge.Bind(h)
```

How a registry device maps onto the broker model:

| Broker field | Registry source |
| --- | --- |
| `Device.ID` | the device ULID string |
| `Device.OrgID` | the organization ULID, empty when the device has none |
| `Device.Subject` | the access token `sub`: the SPIFFE ID when set, else `device:<id>` |
| `Device.Status` | `active`, or `revoked` for any device that is not active |
| `Device.Rules` | allow rules built from the device's enrolled scopes (below) |

The registry device holds a public key, not a certificate or an opaque token. The MQTT credential is therefore the access token the device got from the token endpoint with its signed assertion, sent as the password and checked through `Config.JWT`. A certificate fingerprint never matches a registry device. A subject of the form `device:<id>` is a direct lookup by ID. A SPIFFE subject uses the indexed `DeviceBySPIFFEID` of the storage, and `IdentityStore.DeviceByKeyThumbprint` finds a device by the RFC 7638 thumbprint of its key. Neither lists the fleet. A suspended device is reported with status `suspended`, any other inactive one as `revoked`.

The ACL comes from the device's enrolled scopes, not from the `scope` claim of the token it presents. A scope that starts with `mqtt:` is `mqtt:<action>:<level>:<level>...` where the action is `publish`, `subscribe` or `*`. The levels are the colon segments of the resource naming below, and a final `*` means the rest of the topic:

| Scope | Allow rule |
| --- | --- |
| `mqtt:publish:sensors:temp:*` | publish on `sensors/temp/#` |
| `mqtt:subscribe:devices:{device_id}:cmd:*` | subscribe to `devices/<id>/cmd/#` |
| `mqtt:*:shared:*` | publish and subscribe on `shared/#` |

`{device_id}` and `{org_id}` are replaced when a rule is applied. Other scopes are ignored, and a malformed `mqtt:` scope (a `/`, `+` or `#` inside a level, an empty level, an unknown action) grants nothing. There are no deny rules in this form. To use your own source, set `IdentityStore.Rules`.

### Revocation

`DeviceTokensConfig.OnRevoke` runs after every successful `TheAuth.RevokeDevice` and after the admin revoke route, including a revoke of an already revoked device. `Purger.OnRevoke` drops that device from the handler cache, so the next decision reads the registry and denies with `device_revoked`, without waiting for `CacheTTL`. `Purger.Bind` also clears the cache once, so a revoke that happened before the handler existed is not missed. `Purger.OnStatusChange` does the same for a suspend or resume. The purge is per process unless you set a broadcaster, see below. A client that is already connected still stays connected until the broker rechecks or you kick it.

## Policy engine instead of rules

`PolicyAuthorizer` evaluates [theAuth policies](agent-policies.md) with the resource names of the device identity design: topic levels are colon segments, so the topic `sensors/temp/42` is `mqtt:sensors:temp:42`, the CoAP and ROS 2 resources use the same shape, and the filter `sensors/#` is `mqtt:sensors:*`. The action is `publish` or `subscribe`; the attributes `device_id` and `org_id` are available to `{var}` substitution. `mqttauth.TopicResource` does the conversion.

A topic level that contains a colon cannot be told from a level boundary, so it is denied. The single level wildcard `+` has no resource form, so it is written as `*`, which means a subscription to `a/+` is allowed only by a statement that covers everything under `a`. The TypeScript matcher lets `mqtt:a:*` match `mqtt:a`, as MQTT lets `a/#` match `a`; the authorizer evaluates the resource with and without a trailing colon to get the same result, and a deny on either wins.

```go
Authorizer: mqttauth.PolicyAuthorizer{
    Policies: func(ctx context.Context, d *mqttauth.Device) ([]*policy.Policy, error) { return load(ctx, d.ID) },
},
```

The policy glob `*` matches the MQTT wildcards as text, so an allow on `mqtt:fleet:*` covers the filter `fleet/#`. A glob cannot tell that the filter `#` overlaps a deny on `mqtt:fleet:secret:*`, so for wildcard subscriptions the authorizer also converts every deny and escalate resource into a filter and refuses on overlap. A policy source error denies with `policy_indeterminate`.

## Revocation and caching

Device records and decisions are cached for `CacheTTL` (default 5 seconds, negative disables), at most `CacheMaxEntries` entries. This is the revocation latency when nothing else happens: a device revoked in the store can keep an already cached allow for up to one TTL. To make revocation immediate, call `Handler.Purge(deviceID)` from the code that revokes, or `POST /purge` with `PurgeSecret` from another service or replica. Purge is per process, so with several replicas use a purge broadcaster (next section), call it on each, or keep the TTL short.

A purge also beats a load that was already in flight. Each cache shard keeps a purge epoch, a request takes it before it reads the store, and a cache write made with an older epoch is dropped. So a device read just before a revoke cannot be cached again after `Handler.Purge` (or a broadcast purge) has returned, and the next decision reads the store. The request that was already running can still be answered from the data it read.

Measured on EMQX 5.8.6 and Mosquitto 2.0.15 with the plugin below, on one laptop with the handler on the host and the broker in Docker. A device publishes every 50 ms, the device is revoked in the store about 0.7 seconds after the first publish, and the time to the first denied publish is the number reported. These are single runs on one machine, not a benchmark.

| Setup | EMQX, first denied publish after revoke | Mosquitto, first denied publish after revoke |
| --- | --- | --- |
| `CacheTTL` 5s, no purge (3 runs) | 4190, 4139, 4173 ms | 4139, 4174, 4175 ms |
| `CacheTTL` 1s, no purge (3 EMQX runs, 2 Mosquitto runs) | 173, 141, 147 ms | 181, 131 ms |
| handler cache disabled (`CacheTTL` negative, 2 runs) | 9, 37 ms | 23, 23 ms |
| `CacheTTL` 5s, `Handler.Purge` at the revoke (2 runs) | 18, 33 ms | 54, 15 ms |

The cache entries were filled at connect time, about 0.85 seconds before the revoke, so a 5 second TTL showed 4.1 seconds. The bound is one TTL counted from when the entry was filled, so the worst case is close to the full TTL. `Handler.Purge` was called in process. The `POST /purge` route was exercised separately (`{"purged":N}` for a device, `{"purged":0}` for `all`, 401 for a wrong secret) but its effect on a live session was not timed. After the revoke the client connection stayed open on EMQX and Mosquitto while its publishes were dropped.

Authentication is never cached. A client that is already connected keeps its session until it reconnects or the broker rechecks, which is why `/authn` returns `expire_at`. Pair revocation with a broker side kick (the EMQX clients API) if sessions must end at once.

Revocation does not reach a device that cannot be reached, it only stops new decisions. Offline fleets are handled by short credential lifetimes.

## Audit

Every decision goes to `Config.Audit`, with a `Code` that uses the same values as the TypeScript decision codes: `allowed`, `no_permission`, `policy_indeterminate` (policy or store failure), `device_not_found`, `device_suspended`, `device_revoked`, `device_expired`, and `invalid_credential` for any authentication failure. As in the TypeScript device authenticator, a wrong key, token or unknown certificate all report `invalid_credential`, and only a device whose credential verified reports its blocked state. Denies are always recorded. Allows are sampled at `AllowSampleRate` (default 0.1, 1 records all, negative none) because a publish heavy fleet makes allows the bulk of the volume. Events carry the device, client ID, action, topic, method, a reason, the code and the peer address, never a password or token. `TheAuthSink(auth)` writes `mqtt.authn.allow`, `mqtt.authn.deny`, `mqtt.authz.allow` and `mqtt.authz.deny` rows to the theAuth audit log with `principalType: "device"`, the `code`, and `theauthPrincipal: {"type": "device", "id": ...}`, the marker the TypeScript device module puts on its rows. `SlogSink` writes log records.

## Mosquitto

With `Config.Mosquitto` the routes `/mosquitto/user`, `/superuser` and `/acl` answer the mosquitto-go-auth HTTP backend. Username is the device ID. `acc` 2 is publish, 1 and 4 are subscribe checks, 3 and anything else deny. There are no superusers. A deny is `403` with `{"Ok":false}`, which works in both the `status` and `json` response modes. Both JSON and form encoded requests are accepted. Certificate identity is not available on this contract.

The plugin has no option to send request headers, so these routes accept the broker secret in a `secret` query parameter as well as the bearer header. Put it in the configured URIs. The EMQX routes never accept the query form. A URI is easy to leak: the plugin writes the full URL, secret included, to its log when the request fails (for example when the handler is down). Keep the plugin and this service on a private network or over TLS (`auth_opt_http_with_tls true`), and rotate the secret if a broker log leaves your control. On a loopback only deployment you can set `AllowUnauthenticatedBroker` instead.

Verified against `iegomez/mosquitto-go-auth:latest` (image digest `sha256:acd65f8566f22126e3bf3b72fe5bee8a5002ca57695f211b1904013953560c3f`, built 2023-05-24, Mosquitto 2.0.15, the plugin binary reports no version) with this `mosquitto.conf`:

```conf
listener 1883
allow_anonymous false
auth_plugin /mosquitto/go-auth.so
auth_opt_backends http
auth_opt_http_host auth.internal
auth_opt_http_port 8090
auth_opt_http_getuser_uri /mqtt/mosquitto/user?secret=BROKER_SECRET
auth_opt_http_superuser_uri /mqtt/mosquitto/superuser?secret=BROKER_SECRET
auth_opt_http_aclcheck_uri /mqtt/mosquitto/acl?secret=BROKER_SECRET
auth_opt_http_method post
auth_opt_http_params_mode json
auth_opt_http_response_mode status
auth_opt_http_with_tls false
auth_opt_cache false
```

`params_mode form` with `response_mode json` was also run and gave the same connect, publish and subscribe results. `auth_opt_cache false` matters: the plugin has its own cache, and like the EMQX one it sits in front of this handler.

What the plugin sends, as observed: `/user` gets `username`, `password` and `clientid`. `/acl` gets `username`, `clientid`, `topic` and `acc` as a JSON number. A publish is `acc` 2. A subscribe is `acc` 4 with the filter exactly as the client sent it, including a `$share/<group>/` prefix. Each message delivered to a subscriber is checked again with `acc` 1 and the concrete topic. The handler answers a read check like a subscribe check on that topic, which is why a subscriber with a grant on `devices/<id>/cmd/+` receives the messages the filter covers.

Results, identical on both brokers for the same devices and rules: the connect cases listed under EMQX above, publish allowed only on `devices/<id>/telemetry/#`, the same SUBACK results for plain, `+`, `#`, `$share/` and `$SYS` filters, and the same result for `$share/g1/alerts/+` (granted) and `$share/g1/#` (refused). A denied publish is dropped without disconnecting the client. Mosquitto does not read `expire_at`: the device that EMQX disconnected after 10.4 seconds was still connected after 25 seconds on Mosquitto, so end sessions of expiring devices another way. When the handler is down the plugin refuses the connect.

## What it does not do

MQTT 5 enhanced authentication (AUTH packets, SCRAM, challenge response) needs a broker extension and a stateful exchange, which a stateless HTTP check cannot carry. Use certificate or token credentials here. Per message authorization of retained messages, QoS limits and rate limits are not enforced.

## Purging every replica

`Purger` and `Handler.Purge` act on one process. To reach all replicas, give the `Purger` a `mqttauth.PurgeBroadcaster`, a small interface with `Publish(ctx, deviceID)` and `Subscribe(ctx, fn)`. An empty device ID means everything.

```go
bus := postgres.NewPurgeBroadcaster(pool, "") // channel theauth_device_purge, or name your own
purge.SetBroadcaster(bus)
purge.Bind(h)
go purge.Run(ctx) // every replica runs this, the publisher included
```

`OnRevoke` and `OnStatusChange` purge locally at once and then publish, so the other replicas drop the device as soon as their listener hears it. `postgres.PurgeBroadcaster` uses LISTEN and NOTIFY on the existing pool, with no table or migration, and it holds one pooled connection per `Subscribe`. NOTIFY reaches only connected listeners, so after a reconnect the subscriber reports a purge of everything. A lost message is still bounded by `CacheTTL`. `mqttauth.MemoryPurgeBroadcaster` is the in process version for one replica and for tests. Use a separate channel per environment when they share a database. Implement the interface over NATS or your own bus the same way, or use one of the two below.

**MySQL.** `mysql.NewPurgeBroadcaster(db, interval, retention)` has no LISTEN to use, so `Publish` inserts a row into `theauth_device_purge_events` (migration 0038) and each subscriber polls for rows after its cursor. Zero values mean a 500 ms poll and 10 minutes of retention. Latency is the poll interval. A subscriber starts at the end of the table and never replays old rows. If a poll fails, the next one that works reports a purge of everything, because pruned rows cannot be recovered.

**Redis.** `redispurge.New(redispurge.Config{Addr: "redis:6379", Password: pw, TLS: tlsCfg, Channel: ""})` (package `iot/mqttauth/redispurge`) uses PUBLISH and SUBSCRIBE over a small RESP2 client in the standard library, so it adds no dependency. It supports AUTH with or without an ACL user, and TLS. Redis pub/sub drops messages for disconnected subscribers, so every reconnect reports a purge of everything. Redis Cluster and Sentinel failover are not handled: point `Addr` at one node or a proxy.

## Path matching

`PolicyAuthorizer` takes its resource matching from `policy.Evaluator.ResourceMatching`. The zero value keeps the glob matcher described above. Set `pathmatch.Path` for the matcher shared with the TypeScript core option `resourceMatching: "path"`: a middle `*` segment is exactly one non empty level, `**` is one or more path segments, a final `*` still matches the rest, and a partial glob such as `r*` is literal text.

```go
a := mqttauth.PolicyAuthorizer{
    Evaluator: policy.Evaluator{ResourceMatching: pathmatch.Path},
    Policies:  policiesFor,
}
```

With the glob matcher `mqtt:fleet:*:cmd` also allows `fleet/a/b/cmd` and `fleet//cmd`. In path mode it allows `fleet/a/cmd` only.
