# Visitor signal contract, version 1

Status: draft for slice 1. Applies to both the Go package and the TypeScript package.

A visitor signal is a small set of coarse browser attributes, a few automation flags and a server-computed hash. It is an advisory hint. It is not an identifier of a person, not an authentication factor and not proof of humanity. Expect false merges (identical phones, managed laptops) and false splits (browser updates, setting changes).

## Payload

The machine-readable contract is `schema/v1.json` (JSON Schema 2020-12). Examples and expected outcomes are in `testdata/manifest.json`.

- The browser never computes the visitor hash. It sends coarse components, and the server owns the key and the rotation.
- `v` is the major version only. Additive optional fields are allowed inside a major. The v1 schema is closed (`additionalProperties: false`), so an unknown field is `schema_invalid`, and an additive field ships as a schema update that verifiers adopt. A removed or reinterpreted field bumps `v`.
- A verifier must reject an unsupported `v` with `unsupported_version` before schema validation. It accepts the previous major for one release.
- `status: "suppressed"` carries no components and must carry `suppressedReason`. Any other status must not carry `suppressedReason`.
- `renderHash` is allowed only in `fraud_prevention` mode.
- `ts` is client time and advisory. Freshness comes from the signed challenge, never from `ts`.

### Bucketing rules (client must apply, verifier checks the shape)

| Field | Rule |
| --- | --- |
| `screenBucket` | Each side rounded to the nearest 100 px, then `@` and the device pixel ratio rounded to one decimal. Example: 1512x982 at 2 becomes `1500x1000@2.0`. |
| `cores` | Nearest power of two, capped at 64. |
| `memoryGb` | The value `navigator.deviceMemory` already reports (0.25 to 8). |
| `tzOffsetMin` | Current offset in minutes, range -840 to 840. |
| `uaMajor` | Major version only. |

### Capability bitfield (`caps`)

| Bit | Meaning |
| --- | --- |
| 0 | cookies enabled |
| 1 | localStorage available |
| 2 | sessionStorage available |
| 3 | IndexedDB available |
| 4 | WebGL available (presence only, no renderer string) |
| 5 | WebAssembly available |
| 6 | Intl.DateTimeFormat available |
| 7 | PointerEvent available |
| 8 | Notification API present |
| 9 | Service workers available |

Bits 10 to 31 are reserved. Senders set them to 0.

## Canonicalisation

The hash input is the canonical JSON of `components` only. `flags`, `unavailable`, `status` and every other top-level field are excluded.

1. Serialise as RFC 8785 (JCS) JSON: object keys sorted by UTF-16 code unit order, no whitespace, UTF-8 output.
2. Strings escape only `"`, `\` and control characters below U+0020. In particular `<`, `>` and `&` are not escaped (Go's `encoding/json` escapes them by default, so the Go side needs an encoder with HTML escaping off).
3. Numbers: integers as plain decimal. The only fractional values are `memoryGb` 0.25 and 0.5, written `0.25` and `0.5`. A whole value is written without a fraction (`8`, never `8.0`).
4. Absent components are omitted. A component is never written as `null`.

## Hash and key derivation

```
key  = HKDF-SHA256(ikm = masterSecret, salt = 32 zero bytes,
                   info = "visitor-signal/v1" || 0x00 || siteId || 0x00 || mode || 0x00 || epochId,
                   length = 32)
hash = hex( HMAC-SHA256(key, canonical(components))[0:16] )
```

- The master secret is at least 32 bytes and comes from the integrator's secret store. It is never logged.
- The hash is scoped to one site, one mode and one epoch. The same components under another site, mode or epoch give a different hash.
- Compare hashes in constant time.
- Golden vectors: `testdata/vectors.json`. Both languages must reproduce every `canonical`, `keyHex` and `hash`. The master secret in that file is test-only.

## Epochs

| Mode | Default window | `epochId` format |
| --- | --- | --- |
| `analytics` | UTC day | `d:YYYY-MM-DD` |
| `fraud_prevention` | 30 days, configurable | `w<windowDays>:<index>` where index = floor(days since 1970-01-01 UTC / windowDays) |

The verifier keeps the current and previous epoch keys for a grace window and may return both hashes for lookup. The integrator stores only the current one. The window lengths and the grace window come from configuration, not constants.

## Modes and consent

Consent is a plain input to the server side, not a callback the integrator must implement: `{ consent: granted | denied | unknown, gpc: bool, dnt: bool, routeProtected: bool, lawfulBasis?: "legitimate_interest_security" }`. The browser collector exposes a consent hook that returns the same three states, and `unknown` counts as `denied`.

| Mode | Consent denied or unknown | DNT or GPC set | Route not protected |
| --- | --- | --- | --- |
| `analytics` | `suppressed` (`consent_denied` or `consent_unknown`), no components | `suppressed` (`dnt` or `gpc`), no components | not applicable |
| `fraud_prevention` with `lawfulBasis` asserted and a protected route | runs | bot flags only, no persistent hash | not applicable |
| `fraud_prevention` otherwise | `suppressed` unless consent is granted | bot flags only, no persistent hash | `suppressed` (`route_not_protected`) unless consent is granted |

The fraud-prevention path rests on a contested reading of ePrivacy Art. 5(3). See REFERENCES.md. It is limited to flows the user asked for (login, signup, checkout, password reset), and counsel should review it before any EU launch. Per-site mode values are `off`, `analytics`, `fraud_prevention`, default `off`.

When the collector is blocked or fails, the verifier reports unknown risk, not "bot", so privacy tools are not penalised by default.

## Typed errors

| Code | Meaning |
| --- | --- |
| `unsupported_version` | `v` is not supported |
| `schema_invalid` | payload fails `schema/v1.json` |
| `challenge_invalid` | missing, malformed, bad signature, or bound to another site, route or mode |
| `challenge_expired` | challenge past its TTL |
| `nonce_replayed` | nonce already consumed |
| `mode_not_allowed` | mode not enabled for this site or route |
| `consent_required` | consent missing for the requested mode |
| `rate_limited` | too many requests per IP or per challenge |

## Server response

`{ v, visitorHash, epoch, confidence, riskScore, flags[], mode, reasons[] }`. `confidence` is in [0,1] and is a heuristic, not a calibrated probability. The formula lands with the scoring code in slice 2 and is unit-tested there.

## Configuration, never constants

Challenge TTL, clock skew window, nonce TTL, body size cap, epoch windows, grace window and score cut-offs are read from configuration (environment in the host application). The package ships no hardcoded threshold in a code path.

## Storage and retention

The library persists nothing. The integrator owns storage of hashes, the TTL (match the stated retention), and a delete-by-hash path. Do not store raw components after scoring. Log only reasons and the hash.

## Accuracy limits

Third-party sources put client-only open libraries at roughly 40 to 60 percent accuracy, and a vendor claim of 99.5 percent for a paid server product is not an independent benchmark. We have no measured false-positive rate for this library yet. Do not quote one until the slice 6 measurements exist with their sample size.
