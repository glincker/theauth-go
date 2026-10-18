# Device client library

`iot/device` is the part of theAuth IoT identity that runs on the device (or on a small gateway next to it). It imports only the Go standard library. It can:

- sign a short lived **device assertion** for `Authorization: Bearer <jwt>` (design D3),
- verify a signed **offline policy bundle**, with rollback protection (D7),
- decide offline with `Evaluate(bundle, action, resource)`, using the same rules as the TS `evaluateDeviceBundle`.

The server side lives in the TS core (`theauth.device`, see its `iot-devices` page). Formats are documented so a fleet never depends on this package: any JWT library can produce an assertion.

## Run it

```go
signer, _ := device.NewSigner(devicePrivateKey, nil) // ed25519.PrivateKey or *ecdsa.PrivateKey (P-256, P-384)

// Online: one assertion per request, 60 s by default, 300 s at most.
token, _ := signer.SignAssertion("thermostat-7", now, device.AssertionOptions{})

// Offline: keys come from GET /device/jwks, the bundle from GET /device/bundle.
keys, _ := device.ParseJWKS(jwksJSON)
claims, err := device.VerifyBundle(bundle, device.VerifyOptions{
    Keys: keys, DeviceID: "thermostat-7", LastSeq: storedSeq, Now: now,
})
if err != nil { /* keep using the previous bundle, or deny */ }
storedSeq = claims.Seq // persist it, see rollback below

d := device.Evaluate(claims, "publish", "mqtt:sensors:temp:42", device.WithNow(now))
if !d.Allowed { /* d.Code is one of the TS decision codes */ }
```

A full program is in `examples/device-client` (its own module, not in `go.work`; run with `GOWORK=off go run .`).

## What `Evaluate` does

Rule for rule the same as the TS side:

1. The bundle is expired once `now > exp + 30 s`: `device_expired`.
2. The first permission whose resource and action match decides. Resources are colon segments, a `*` segment matches the rest, `*` alone matches everything. When the server signs `"rm": "path"` into the bundle (its `resourceMatching: "path"` option), `Evaluate` uses the path aware matcher of package `policy/pathmatch` instead: inside one colon segment `/` separates path segments, `*` is one segment, `**` is one or more, never an empty, `.` or `..` segment, nothing is decoded, and a partial glob is literal. `Claims.ResourceMatching` carries the mode, and the Go and TypeScript matchers are checked against each other with generated vectors. Actions match by name or `*`.
3. Constraints, in server order: `maxCallsPerHour`, `allowedArgPatterns`, `requireApproval`, `timeWindow`, `ipAllowlist`. Two fail closed rules apply offline. `requireApproval` always denies (`approval_required`), because no human is reachable. A rate limited permission denies (`rate_limited`) unless you pass your own count with `WithCallsInLastHour`.
4. No audit rows exist offline. Queue your decisions and upload them when you are back online.

Pass arguments with `WithArguments`, the caller address with `WithIP`. Resource names follow design D8: topic `sensors/temp/42` is `mqtt:sensors:temp:42`, CoAP `/actuators/valve` is `coap:actuators:valve`.

### Where Go differs from TS, on purpose

| Case | TS | Go |
| --- | --- | --- |
| Bundle without `exp` | accepted | refused (`invalid`). The server never issues one. |
| Bundle header without `kid` | accepted if one key fits | refused |
| `allowedArgPatterns` syntax | JavaScript RegExp | Go RE2. A pattern RE2 cannot compile (for example a lookahead) denies. Keep device patterns to the common subset. |
| `timeWindow` zone | server local time | UTC unless you pass `WithLocation`. Use the zone of the server that issued the bundle. |
| Malformed permission entry | throws | dropped, so it grants nothing |

Everything else is checked by shared vectors (below).

## Rollback protection

Every bundle has `seq`, its issue time in milliseconds. Store the highest `seq` you accepted in flash and pass it as `LastSeq`. Without it, an attacker who captures an older, wider bundle can replay it until it expires. Persist it only after a successful `VerifyBundle`.

## Devices without a clock

A microcontroller with no battery backed RTC boots at an arbitrary time and cannot judge `exp` or an assertion's `iat`. `SyncedClock` handles it:

- Anchor it to a time you have just authenticated: the `iat` of a bundle that passed `VerifyBundle`, or the `Date` header of a TLS response from your server.
- It then adds elapsed time from a monotonic counter you give it (`time.Since(boot)` or a hardware tick). Every MCU has one.
- Before the first `Sync`, `Now` reports false. Deny everything until you have a time.
- The anchor only moves forward. A `Sync` more than 30 s behind the estimate is ignored, so replaying an older signed bundle cannot drag the clock back and revive an expired one. Combined with `LastSeq`, a stolen old bundle is useless.

Bootstrap order for a cold device: connect, fetch the bundle, verify its signature with a clock that is allowed to be wrong only for the `exp` and `nbf` checks (pass `Now` as the bundle's own `iat` for that first call), then `Sync(iat)` and use the clock from then on. The cost is that the very first bundle cannot be proven fresh, only authentic. The 30 s skew rule and the one hour default bundle lifetime bound the damage. If your hardware has no way to trust any time at first boot, treat first boot as online only.

## Ed25519 or ES256 on a small MCU

Both work in this package. Our reading of the sources (links below):

- Ed25519 signs deterministically. ECDSA needs a fresh unpredictable nonce per signature, and a weak or repeated one lets an attacker recover the private key. On a part without a trustworthy RNG, that is the main risk, and it is the reason we suggest Ed25519 by default. RFC 6979 makes ECDSA deterministic too, but the Go `crypto/ecdsa` signer here is randomized, so supply a good `rng` to `NewSigner` if you use ES256.
- Ed25519 is usually faster than P-256 ECDSA in software, and its signatures (64 bytes) and keys (32 bytes) are small.
- ES256 is the better choice when the private key lives in a secure element or crypto peripheral that only speaks P-256 (many do), or when your fleet already standardizes on P-256.
- Both are accepted by the server for device keys. Bundles are signed with ES256 or EdDSA. ES384 is accepted for assertions only.

We did not benchmark either on hardware, so we make no speed claim for a specific chip.

## TinyGo

TinyGo was not installed where this package was built, so a TinyGo build is **not verified**. What was done to make it likely:

- The package imports no `encoding/json`, `reflect`, `fmt`, `os` or `sort` directly (a test enforces this). JSON is read by a small built in parser. The TinyGo porting guide says its `reflect` support is limited and that `encoding/json` is the usual casualty.
- The standard crypto packages pull `reflect` and `fmt` in internally on regular Go. Whether TinyGo links `crypto/ecdsa`, `crypto/ed25519` and `regexp` for your target is a TinyGo question: check its [supported packages table](https://tinygo.org/lang-support/stdlib) for your version before you commit to hardware.
- If `regexp` is too large for your part, do not use `allowedArgPatterns` on the server for that fleet. Evaluation of other constraints never touches it.

## Interop with the TS reference

`iot/device/testdata/vectors.json` holds TS generated cases: 26 bundle verification cases (both algorithms, skew edges, wrong device, rollback, forged and tampered tokens), 54 evaluation cases (constraint order, windows, CIDR quirks, expiry edges), 13 TS signed assertions and JWK thumbprints. `go test ./iot/device` replays them. Regenerate with:

```sh
TZ=UTC node docs-local/vectors/gen-device-vectors.mjs
```

The script bundles the TS source in memory and writes nothing to the TS repo. The other direction (Go signs, TS verifies):

```sh
GO_DEVICE_INTEROP_OUT=/tmp/interop.json go test ./iot/device -run TestWriteInterop
node docs-local/vectors/check-go-interop.mjs /tmp/interop.json
```

## Sources

- TinyGo supported packages: https://tinygo.org/lang-support/stdlib and porting guide https://tinygo.org/docs/guides/compatibility/
- RFC 7523 (assertion layout), RFC 9449 (replay rules), RFC 7638 (JWK thumbprint), RFC 8032 and RFC 8037 (Ed25519 in JOSE), RFC 6979 (deterministic ECDSA), RFC 8725 (JWT best practice)
- Nonce reuse and key leakage in ECDSA and EdDSA: https://www.elliptic.co/corpus/gen-3462/key-signature-cryptography/nonce-reuse-and-key-leakage-risks-in-ecdsa-and-eddsa-signatures.html
