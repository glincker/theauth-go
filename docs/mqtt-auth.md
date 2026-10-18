# MQTT broker authentication and authorization

The `iot/mqttauth` package answers the two questions an MQTT broker asks over HTTP: may this client connect, and may it publish to or subscribe to this topic. It speaks the EMQX 5 HTTP authenticator and authorizer contracts and, behind a flag, the mosquitto-go-auth HTTP backend contract. HiveMQ is covered by the same endpoints through its HTTP extension or a small extension that calls them.

Devices are principals from a `DeviceStore`. The package ships a memory store and a `database/sql` store for SQLite and PostgreSQL. It does not issue credentials: tokens come from [device tokens](device-tokens.md) or your own provisioning, and the broker only asks.

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

## Policy engine instead of rules

`PolicyAuthorizer` evaluates [theAuth policies](agent-policies.md) with resource `mqtt:topic/<name or filter>` and action `publish` or `subscribe`; the attributes `device_id` and `org_id` are available to `{var}` substitution.

```go
Authorizer: mqttauth.PolicyAuthorizer{
    Policies: func(ctx context.Context, d *mqttauth.Device) ([]*policy.Policy, error) { return load(ctx, d.ID) },
},
```

The policy glob `*` matches the MQTT wildcards as text, so an allow on `mqtt:topic/fleet/*` covers the filter `fleet/#`. A glob cannot tell that the filter `#` overlaps a deny on `mqtt:topic/fleet/secret/*`, so for wildcard subscriptions the authorizer also converts every deny and escalate resource into a filter and refuses on overlap. A policy source error denies.

## Revocation and caching

Device records and decisions are cached for `CacheTTL` (default 5 seconds, negative disables), at most `CacheMaxEntries` entries. This is the revocation latency when nothing else happens: a device revoked in the store can keep an already cached allow for up to one TTL. To make revocation immediate, call `Handler.Purge(deviceID)` from the code that revokes, or `POST /purge` with `PurgeSecret` from another service or replica. Purge is per process, so with several replicas call it on each, or keep the TTL short.

Authentication is never cached. A client that is already connected keeps its session until it reconnects or the broker rechecks, which is why `/authn` returns `expire_at`. Pair revocation with a broker side kick (the EMQX clients API) if sessions must end at once.

Revocation does not reach a device that cannot be reached, it only stops new decisions. Offline fleets are handled by short credential lifetimes.

## Audit

Every decision goes to `Config.Audit`. Denies are always recorded. Allows are sampled at `AllowSampleRate` (default 0.1, 1 records all, negative none) because a publish heavy fleet makes allows the bulk of the volume. Events carry the device, client ID, action, topic, method, a reason and the peer address, never a password or token. `TheAuthSink(auth)` writes `mqtt.authn.allow`, `mqtt.authn.deny`, `mqtt.authz.allow` and `mqtt.authz.deny` rows to the theAuth audit log with `principalType: "device"`. `SlogSink` writes log records.

## Mosquitto

With `Config.Mosquitto` the routes `/mosquitto/user`, `/superuser` and `/acl` answer the mosquitto-go-auth HTTP backend. Username is the device ID. `acc` 2 is publish, 1 and 4 are subscribe checks, 3 and anything else deny. There are no superusers. A deny is `403` with `{"Ok":false}`, which works in both the `status` and `json` response modes. Both JSON and form encoded requests are accepted. Certificate identity is not available on this contract.

## What it does not do

MQTT 5 enhanced authentication (AUTH packets, SCRAM, challenge response) needs a broker extension and a stateful exchange, which a stateless HTTP check cannot carry. Use certificate or token credentials here. Per message authorization of retained messages, QoS limits and rate limits are not enforced.
