// Package signals implements the OpenID Shared Signals Framework 1.0
// (SSF), with the CAEP and RISC event vocabularies, on top of Security Event
// Tokens (RFC 8417).
//
// It has three halves that can be used independently:
//
//   - SET creation and verification (NewSET, Sign, Verify).
//   - A Transmitter that serves the SSF metadata and stream management API
//     and delivers SETs by push (RFC 8935) or poll (RFC 8936).
//   - A Receiver that accepts pushed SETs, verifies them against the
//     issuer's JWKS, drops replays, and dispatches to pluggable handlers.
//
// The package does not import the root theauth package, so it can be used
// standalone. Config.SharedSignals in the root package wires the Transmitter
// to the authorization server signing keys and the audit event stream.
package signals
