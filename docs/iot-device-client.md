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

Checked on 2026-10-18 with TinyGo 0.43.0 (Go 1.27.2, LLVM 22.1.4, the `tinygo/tinygo` Docker image on linux/arm64). Everything below was run, nothing is a guess, except where it says "not run".

**Tests.** `tinygo test ./iot/device` passes: the whole package suite, including the 100+ shared vectors, runs under TinyGo (on the host target, not on a microcontroller).

**Smoke program.** `iot/device/internal/tinygocheck` signs a bundle with a fixed test seed, verifies it, evaluates an allowed and a denied request, then signs and verifies an assertion. It prints `OK` or exits non zero. It uses only `println`, not `log` or `fmt`.

```sh
docker run -v "$PWD":/src:ro -w /src -e GOWORK=off tinygo/tinygo:latest \
  tinygo build -o /tmp/check.wasm -target=wasip1 ./iot/device/internal/tinygocheck
```

Results for that program, full build (ES256, ES384 and Ed25519) and with `-tags theauth_noecdsa` (Ed25519 only, see below). Sizes are `tinygo build -size=short`, in bytes:

| Target | Chip | Full build | `theauth_noecdsa` |
| --- | --- | --- | --- |
| `pca10056` | nRF52840, 1 MB flash, 256 kB RAM | flash 544,596, RAM 211,508 | flash 274,100, RAM 121,448 |
| `pico` | RP2040, 2 MB flash, 264 kB RAM | flash 656,060, RAM 213,360 | flash 306,476, RAM 123,288 |
| `feather-m4` | SAMD51, 512 kB flash, 192 kB RAM | does not fit (flash over by 40,472, RAM over by 17,996) | flash 277,780, RAM 124,552 |
| `cortex-m-qemu` | LM3S6965, 256 kB flash, 64 kB RAM | does not fit (flash over by 284,192, RAM over by 146,376) | does not fit (flash over by 10,448, RAM over by 56,296) |
| `arduino-nano33`, `microbit` | SAMD21 (256 kB flash, 32 kB RAM), nRF51 (256 kB flash, 16 kB RAM) | does not fit | not built with the tag |
| `esp32-coreboard-v2` | ESP32 | linker error, `.data` does not fit the DRAM region | not built with the tag |
| `wasip1` | WebAssembly (WASI) | builds, 4.3 MB | builds, 1.7 MB |
| `wasm` | WebAssembly (browser) | builds | not built with the tag |

The `wasip1` programs were also executed, under Node 22's WASI (`node:wasi`), in both variants. Both print `OK` and exit 0, so the JSON reader, JWS verification, Ed25519, ES256 and the evaluator all work under TinyGo at runtime. Not run: any microcontroller binary (no board, and no QEMU image was installed), so flash and RAM above are link time figures. `esp32c3` is an inheritable only target and was not built. A real program also needs your networking and storage, which these numbers do not include.

What takes the space. With the full build, `crypto/internal/fips140/nistec` (the P-256 and P-384 code) holds about 88 kB of RAM in tables, and `edwards25519` about 38 kB. Both come from the Go standard library's crypto, not from this package. `math/big` and `regexp` add roughly 25 kB and 30 kB of flash. If your server signs bundles, revocation snapshots and device keys with Ed25519, build with the tag:

```sh
tinygo build -tags theauth_noecdsa -target=pico ./cmd/yourdevice
```

`theauth_noecdsa` (files `keys_ecdsa.go` and `keys_noecdsa.go`) removes every ECDSA path, so `crypto/ecdsa`, `crypto/elliptic` and `math/big` are not linked. ES256 and ES384 keys, tokens and signers are then refused as unsupported. It cut RAM by about 90 kB and flash by about 270 kB on `pico` and `pca10056`. The package tests use ES256 vectors, so they only run in the default build. `go vet -tags theauth_noecdsa ./iot/device/...` checks that the variant compiles.

What was already in place and held up: the package imports no `encoding/json`, `reflect`, `fmt`, `os` or `sort` directly (a test enforces this), and JSON is read by a small built in parser. TinyGo's `reflect` support is limited, so this mattered. `regexp` links and works. If `regexp` is too large for your part, do not use `allowedArgPatterns` for that fleet: the other constraints never touch it.

Not changed: `crypto/rand` is still imported for the ECDSA nonce default. TinyGo links it on every target above. On a part without a hardware random source, use Ed25519 (deterministic), or pass your own `rng` to `NewSigner`.

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

- TinyGo supported packages: https://tinygo.org/lang-support/stdlib, porting guide https://tinygo.org/docs/guides/compatibility/ and binary size guide https://tinygo.org/docs/guides/optimizing-binaries/
- RFC 7523 (assertion layout), RFC 9449 (replay rules), RFC 7638 (JWK thumbprint), RFC 8032 and RFC 8037 (Ed25519 in JOSE), RFC 6979 (deterministic ECDSA), RFC 8725 (JWT best practice)
- Nonce reuse and key leakage in ECDSA and EdDSA: https://www.elliptic.co/corpus/gen-3462/key-signature-cryptography/nonce-reuse-and-key-leakage-risks-in-ecdsa-and-eddsa-signatures.html
