// Package checkpoint implements signed audit checkpoints, Merkle inclusion and
// consistency proofs, and portable receipts, wire compatible with the
// TypeScript SDK (packages/core/src/audit/checkpoint*.ts).
//
// A checkpoint is a signed tree head over the chained audit rows: an RFC 6962
// Merkle tree (leaf hash SHA-256(0x00 || data), node hash
// SHA-256(0x01 || left || right)), a root, a size and an Ed25519 signature. An
// inclusion proof shows one row is a leaf of that tree. A consistency proof
// shows a newer checkpoint extends an older one without rewriting a row. A
// receipt bundles one row's decision (only the fields the caller chose to
// reveal, the rest as salted commitments), its inclusion proof and the
// checkpoint, so a counterparty can verify it offline with only the public key.
//
// Wire format (identical to the TypeScript SDK): JSON field names as in the
// struct tags, hashes as lowercase hex, signatures as unpadded base64url, and
// canonical JSON (keys sorted by UTF-16 code unit, JavaScript number and
// string formatting) for every hashed or signed value. The signed message is
// "theauth.audit.checkpoint.v1\n" followed by the canonical JSON of version,
// alg, keyId, size, rootHash, timestamp, since and until.
//
// Rows come from a Source. EventSource adapts a store that implements
// QueryAuditEvents (the sqlite, postgres and mysql stores chain their rows).
// Rows read from the Go chain use hash version GoChainHashVersion and their own
// receipt field set (see GoChainFields); the TypeScript field sets for hash
// versions 1 and 2 are also understood, so a TypeScript receipt verifies here.
package checkpoint
