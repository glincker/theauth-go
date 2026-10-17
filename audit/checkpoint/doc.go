// Package checkpoint implements signed audit checkpoints, Merkle inclusion and consistency proofs,
// and portable receipts, wire compatible with the TypeScript SDK. A checkpoint is an Ed25519 signed
// RFC 6962 tree head over the chained audit rows, so a counterparty can verify a receipt offline
// with only the public key.
package checkpoint
