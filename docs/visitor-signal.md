# Visitor signal

`github.com/glincker/theauth-go/visitorsignal` is a small, stdlib-only Go module for privacy-first visitor hints. A matching browser collector lives in the TypeScript SDK as `@glinr/theauth-visitor-signal`.

It produces hints, not identities. A visitor signal is a handful of coarse browser attributes, a confidence score, bot and automation flags, and a hash that only the server can compute. Use it for rough returning-visitor counts and for spotting automated traffic. Do not use it to authenticate anyone, and do not use it as the only basis for a legal or financial decision.

## What it is not

- Not cross-site tracking. Every hash is scoped to one site, one mode and one epoch.
- Not a person identifier. There are no IP addresses, font lists, GPU strings or raw canvas data in the contract.
- Not an anti-fingerprinting bypass. Browsers that normalise or randomise values are detected and scored lower, not fought.
- Not a measured product yet. There is no benchmark of its false merge or false split rates. Third-party estimates for open client-only libraries sit around 40 to 60 percent accuracy, and that is not a figure for this library.

## Modes

| Mode | Purpose | Needs |
| --- | --- | --- |
| `analytics` | Unique visitors within a day, bot filtering | Consent, no Do Not Track, no Global Privacy Control |
| `fraud_prevention` | Abuse signals on login, signup, checkout | Consent, or a stated security basis on a protected route |

In `analytics` mode the hash rotates daily. In `fraud_prevention` mode the default window is 30 days. The full decision table is in `visitorsignal/SPEC.md`.

## Legal note

This is not legal advice. Reading device attributes falls under ePrivacy Art. 5(3) according to the EDPB Guidelines 2/2023, so analytics use normally needs consent. Whether fraud prevention is "strictly necessary" under that article is contested and depends on the Member State. We found no primary source that confirms a blanket exemption. Keep `fraud_prevention` to flows the user asked for, and get counsel to review it before an EU launch.

## What the Go package does today

- `ValidatePayload` strictly decodes the browser payload against the v1 contract.
- `Canonicalise` and the hasher produce the salted, rotating, per-site hash.
- `Decide` applies the consent, Do Not Track and Global Privacy Control rules.
- `Score` and `Assess` return a heuristic confidence and a bot risk with reasons.
- `Sketch` and `Similarity` are optional and let two records match after one attribute drifts, such as a browser update.
- `ParseSignalV1` and `ComputeSignalV1Digest` handle the compact digest object some consumers want.

Challenge tokens, the nonce store, the verifier and the HTTP handler are not built yet.

## Retention

The library stores nothing. The caller decides where hashes live, how long, and how a visitor is deleted. Keep the retention period equal to what you tell your users, and never store raw components after scoring.
