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
- In `analytics` mode a payload with `flags.dnt` or `flags.gpc` true must be `suppressed`. Any other status is `schema_invalid`.
- A JSON object that repeats a key, at any depth, is `schema_invalid`.
- `ts` is client time and advisory. Freshness comes from the signed challenge, never from `ts`.

### Bucketing rules (client must apply, verifier checks the shape)

| Field | Rule |
| --- | --- |
| `screenBucket` | Each side rounded to the nearest 100 px, then `@` and the device pixel ratio rounded to one decimal. Example: 1512x982 at 2 becomes `1500x1000@2.0`. |
| `cores` | Nearest power of two, ties round up (6 becomes 8, 3 becomes 4), capped at 64. |
| `memoryGb` | The value `navigator.deviceMemory` already reports (0.25 to 8). |
| `tzOffsetMin` | Current offset in minutes, range -840 to 840. |
| `uaMajor` | Major version only. When a Chromium brand is present (`Chrome`, `Google Chrome`, `Chromium`, `Microsoft Edge`, `Brave`), it is the Chromium major, the same number as `Chrome/N` in the User-Agent. Forks such as Opera, Samsung Internet and Yandex may report their own major, and the server skips the User-Agent cross-check for them. |

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

## Part 2: decisions added in slice 2

Vectors for everything below are in `testdata/vectors-extra.json` (generated by an independent reference implementation).

### SignalV1 profile (cookieless digest for same-origin beacons)

Some consumers want a single opaque digest from the browser and apply their own keyed hash on the server. The collector can emit this object in analytics mode only:

```json
{ "v": 1, "source": "browser", "digest": "<base64url, 32 bytes, no padding>", "confidence": 0.0, "components": 9, "ts": 1763452800 }
```

- `ts` is epoch seconds. `components` is the number of components that contributed. No other fields. Consumers decode strictly and reject unknown fields. The body is at most 512 bytes.
- For each component: `h_i = SHA-256(name || 0x00 || canonicalValue)` where `canonicalValue` is the RFC 8785 serialisation of that one value.
- Sort the pairs by component name (byte order), concatenate the raw 32-byte `h_i` values, then `digest = SHA-256(pepper || 0x00 || concat)`. `pepper` is a public per-site string supplied by the page, so digests do not correlate across sites.
- `confidence` is computed in the browser, so it is advisory. A forger can set any digest or confidence, so this profile must never gate a security decision. Consumers use it for analytics only.
- This profile has no challenge, no nonce and no server cross-checks. Use the full payload with the verifier when those matter.

### Confidence model

A heuristic, not a calibrated probability. Defaults live in a `ConfidenceModel` struct that the integrator can override from configuration. Start at `base`, subtract, clamp to [0, 1], then round to 4 decimals. The mobile Safari and Android terms are mutually exclusive: test mobile Safari first, and when it matches do not apply the Android term. Vectors are in `testdata/vectors-extra.json` under `confidence`.

| Term | Default |
| --- | --- |
| base | 0.90 |
| analytics mode (low-entropy sources only) | -0.15 |
| mobile Safari (platform `iPhone` or `iPad`, or `mobile` true with `uaBrand` Safari) | -0.30 |
| Android (`platform` starts with `Linux armv` or `Android`, with `mobile` true) | -0.20 |
| `flags.protectedBrowser` | -0.30 |
| `flags.inconsistent` | -0.20 |
| each entry in `unavailable` | -0.05, total capped at -0.25 |
| fewer than 6 components | -0.10 |

### Bot and automation risk

`riskScore` is in [0, 1], the sum of the weights below, capped at 1. It is a score, not a verdict. `reasons` lists the machine codes that fired. `protectedBrowser` alone never adds risk.

| Reason code | Weight | Condition |
| --- | --- | --- |
| `webdriver` | 0.60 | `flags.webdriver` |
| `automation_globals` | 0.30 | `flags.automationGlobals` > 0 |
| `headless_hint` | 0.30 | `flags.headlessHint` |
| `inconsistent` | 0.20 | `flags.inconsistent` |
| `no_input` | 0.10 | `flags.noInputObserved`, fraud_prevention mode only |
| `ua_missing` | 0.30 | request `User-Agent` empty |
| `ua_major_mismatch` | 0.30 | payload `uaMajor` differs from the request `User-Agent` major, chosen by `uaBrand`: `Chrome/N` for the Chromium brands above, `Firefox/N` for `Firefox`, `Version/N` for `Safari`. Skipped for any other brand or when `uaBrand` is absent |
| `mobile_mismatch` | 0.20 | payload `mobile` disagrees with `Sec-CH-UA-Mobile` when that header is present |
| `platform_mismatch` | 0.20 | payload `platform` family (Win, Mac, Linux, iPhone, iPad, Android) disagrees with `Sec-CH-UA-Platform` when that header is present, otherwise with the request `User-Agent` (Android Chrome in desktop-site mode sends a desktop User-Agent) |
| `language_mismatch` | 0.10 | primary subtag of payload `lang` is absent from `Accept-Language`, when `Accept-Language` is present |

Anything the server observes outranks what the client claims. A blocked or failed collector yields unknown risk, never a bot verdict.

### Drift-tolerant sketch (optional, off by default)

Exact hashes split a visitor when one attribute changes (a browser update). The optional sketch stores one short keyed hash per component, so two records can be compared without raw values:

```
sketchKey = HKDF-SHA256(master, salt = 32 zero bytes,
            info = "visitor-signal/v1/sketch" || 0x00 || siteId || 0x00 || mode || 0x00 || epochId, 32)
sketch[name] = hex( HMAC-SHA256(sketchKey, name || 0x00 || canonicalValue)[0:4] )
```

`Similarity(a, b)`: take the names present in both sketches. If fewer than 5, return 0. Otherwise the result is the weight of equal components divided by the weight of all shared components, using the weights in `testdata/vectors-extra.json`, rounded to 4 decimals. A sketch reveals per-component equality between stored records, so it carries more linkage than the single hash. It stays inside one site, mode and epoch, and the integrator opts in and sets its retention.

### Challenge token

`token = base64url(payload) || "." || base64url(HMAC-SHA256(challengeKey, payload))` with `payload` a JSON object `{"v":1,"site":"...","mode":"...","route":"...","nonce":"...","iat":<epoch s>,"exp":<epoch s>}` and `challengeKey = HKDF-SHA256(master, salt = 32 zero bytes, info = "visitor-signal/v1/challenge", 32)`. The verifier checks the signature in constant time, `exp`, and that site, mode and route match, then consumes `nonce` in the `NonceStore` (atomic set-if-absent with TTL). The payload `nonce` must equal the body `nonce`.
