# Shared Signals Framework (SSF, CAEP, RISC)

theauth-go can act as an OpenID Shared Signals Framework 1.0 transmitter and receiver. Security events travel as Security Event Tokens (RFC 8417), delivered by push (RFC 8935) or poll (RFC 8936), using the CAEP and RISC event vocabularies.

The code lives in the `signals` package, which does not import the root package and can be used on its own. `Config.SharedSignals` wires it to the authorization server signing keys and the audit event stream.

## Transmitter

```go
auth, err := theauth.New(theauth.Config{
    Storage: store,
    AuthorizationServer: &theauth.AuthorizationServerConfig{Issuer: "https://auth.example.com"},
    SharedSignals: &theauth.SharedSignalsConfig{
        // Who is calling the stream API? Validate your access token here and
        // return a stable receiver id that owns the streams it creates.
        Authenticate: signals.StaticBearerAuth(map[string]string{"s3cret": "relying-party-1"}),
        EmitFromAudit: true,                  // opt in to automatic emission
        Store: sqliteStore.SignalsStore(),    // or postgresStore.SignalsStore()
    },
})

// Mount at the issuer origin so the well-known path resolves.
router.Handle("/.well-known/ssf-configuration", auth.SharedSignalsHandler())
router.Handle("/ssf/*", auth.SharedSignalsHandler())
```

SETs are signed with the authorization server EdDSA key and verify against `<issuer>/oauth/jwks`. Header `typ` is `secevent+jwt`. There is no `exp` claim (RFC 8417 section 2.2). The push loop starts with `New` and stops with `Close`.

### Endpoints

| Method and path | Purpose |
| --- | --- |
| `GET /.well-known/ssf-configuration` | Transmitter metadata (public) |
| `POST /ssf/stream` | Create a stream (`delivery`, `events_requested`, `aud`, `description`) |
| `GET /ssf/stream[?stream_id=]` | Read one stream or list the caller's streams |
| `PATCH` or `PUT /ssf/stream` | Update or replace a stream |
| `DELETE /ssf/stream?stream_id=` | Delete a stream, its subjects and queued events |
| `GET /ssf/status?stream_id=`, `POST /ssf/status` | Read or set `enabled`, `paused`, `disabled` |
| `POST /ssf/subjects/add`, `POST /ssf/subjects/remove` | Maintain the subject filter |
| `POST /ssf/verify` | Queue a verification event with a `state` |
| `POST /ssf/poll/{stream_id}` | Poll delivery: `ack`, `maxEvents`, `returnImmediately`, `setErrs` |

Streams belong to the receiver that created them; other receivers get 404.

### Delivery

- Push: the SET is POSTed with `Content-Type: application/secevent+jwt` and the stream's `authorization_header`. A 2xx acknowledges it. Network errors, 408, 429 and 5xx retry with exponential backoff (`BackoffBase` 2s doubling to `BackoffMax` 15m, `MaxAttempts` 8). Any other status drops the SET.
- Poll: unacknowledged SETs are returned again until acknowledged. `moreAvailable` is set when `maxEvents` cut the page. Long polling waits up to 30s unless `returnImmediately` is true.
- A stream with no registered subjects receives every event of its requested types. Once a subject is added, only events about registered subjects are delivered (a complex subject matches on any registered member).
- A `paused` stream keeps queueing and delivers after it is enabled again. A `disabled` stream drops events.

### SSRF protection

Push URLs are validated at stream create or update and again before each delivery: `https` only, no credentials or fragment, no `localhost`, `.local` or `.internal` names, and no host that is or resolves to a loopback, private, link-local, CGNAT or metadata address. The delivery client also refuses non-public addresses at dial time, so DNS rebinding cannot bypass the check, and it never follows redirects. `AllowPrivateNetworks` and `AllowInsecureHTTP` exist for tests and closed networks.

### Event types and automatic emission

| Event | Type URI suffix | Emitted automatically from |
| --- | --- | --- |
| CAEP session-revoked | `caep/event-type/session-revoked` | single session revoke, logout, sign out other sessions |
| RISC sessions-revoked | `risc/event-type/sessions-revoked` | `RevokeUserSessions` |
| CAEP credential-change | `caep/event-type/credential-change` | password change, passkey add or remove, TOTP enroll or disable |
| RISC account-disabled | `risc/event-type/account-disabled` | `DisableUser` |
| RISC account-enabled | `risc/event-type/account-enabled` | `EnableUser` |
| CAEP token-claims-change, assurance-level-change, device-compliance-change; RISC credential-compromise | | host code only |

Emit the host-driven events through the transmitter:

```go
tx := auth.SharedSignalsTransmitter()
err := tx.Emit(ctx, signals.NewCredentialCompromise(
    signals.EmailSubject("alice@example.com"), time.Now(), "password", "found in breach corpus"))
```

Subject identifiers: `iss_sub`, `email`, `opaque`, `phone_number`, `account`, `did`, `uri`, and complex subjects (`signals.ComplexSubject`). Automatic events use `iss_sub` with the issuer and the user id; override with `SharedSignalsConfig.SubjectFor`.

## Receiver

```go
SharedSignals: &theauth.SharedSignalsConfig{
    Authenticate: ...,
    Receiver: &theauth.SharedSignalsReceiverConfig{
        Audience:     "https://app.example.com/ssf-receive",
        Issuers:      map[string]string{"https://idp.example": ""}, // iss -> optional jwks_uri
        Authenticate: func(r *http.Request) bool { return r.Header.Get("Authorization") == "Bearer " + pushSecret },
    },
},

router.Handle("/ssf-receive", auth.SharedSignalsReceiverHandler())
```

The receiver accepts only trusted issuers, discovers keys from `<issuer>/.well-known/ssf-configuration` (or the configured `jwks_uri`) through the SSRF-guarded client, refetches on an unknown `kid`, requires `typ` `secevent+jwt`, checks `aud`, and drops replays by `iss` plus `jti` for 24h. A replayed SET is acknowledged with 202 without running handlers again. Failures answer 400 with the RFC 8935 `err` codes. A handler error answers 500 so the transmitter retries.

The default handler revokes every local session of the user on `session-revoked`, `sessions-revoked` and `account-disabled`. Subjects resolve by email address (or the `user` member of a complex subject); set `ResolveUser` to map other formats. Revocations received this way are not re-emitted, which prevents two peers from echoing each other forever. Add your own `Handlers`, or set `DisableDefaultRevocation`.

## Storage

`signals.NewMemoryStore` is the default and loses queued events on restart. `SignalsStore()` on the sqlite store (migration `0012_shared_signals`) and the postgres store (migration `0026_shared_signals`) persist streams, subjects and the queue. The MySQL store has no signals store yet. Custom stores implement `signals.Store` and can be checked with `signals/storetest`.

## Limits

- Only the EdDSA authorization server key signs SETs.
- Stream management authentication is yours to provide through `Authenticate`; there is no built-in OAuth scope check.
- The push loop and the queue are per process. Several replicas sharing a store can deliver the same SET twice (receivers dedupe on `jti`).
- Events `stream-updated`, subject `verified` handling and `default_subjects` other than `NONE` are not implemented.
