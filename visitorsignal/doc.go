// Package visitorsignal validates, canonicalises and hashes coarse browser
// signals for advisory bot and repeat-visit hints. It uses only the standard
// library and persists nothing; the host application owns secrets, storage
// and retention. The contract is in SPEC.md and schema/v1.json.
//
// The browser sends coarse components and automation flags. The server owns
// the key: ValidatePayload checks the shape, Canonicalise fixes the hash
// input, and Hasher turns it into a per-site, per-mode, per-epoch hash.
// Confidence, Assess and Decide cover scoring, automation risk and consent.
//
// Limits to state plainly to users of this package. Every output is a
// heuristic and advisory. It is not an authentication factor, not proof of
// humanity and not an identifier of a person. Expect false merges (identical
// phones, managed laptops) and false splits (browser updates, setting
// changes). No false-positive rate has been measured yet, so none should be
// quoted. A blocked or failed collector means unknown risk, never a bot
// verdict. The SignalV1 digest and the sketch are weaker still: the digest is
// forgeable by the client, and the sketch reveals per-component equality.
package visitorsignal
