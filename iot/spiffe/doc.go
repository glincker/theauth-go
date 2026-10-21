// Package spiffe is the SPIFFE workload identity bridge: a workload presents an X.509-SVID or a
// JWT-SVID, the package verifies it against a trust bundle you configure, and maps the SPIFFE ID to
// an existing theAuth device through Storage.DeviceBySPIFFEID. Nothing is created on the fly.
//
// The rules follow the SPIFFE specifications (SPIFFE-ID.md, X509-SVID.md, JWT-SVID.md and the trust
// domain and bundle document at https://github.com/spiffe/spiffe/tree/main/standards) and mirror the
// TypeScript implementation (sdk/packages/core/src/device/spiffe) rule for rule. testdata/vectors.json
// is generated from the TS code (docs-local/vectors/gen-spiffe-vectors.mjs) and replayed by the tests,
// so both sides agree on every refusal code.
//
// An X.509-SVID gives the RFC 8705 confirmation member x5t#S256 (Result.CNF). The caller must
// already know the peer holds the leaf key: pass the chain from a TLS handshake your server verified
// (tls.ConnectionState.PeerCertificates), never a certificate taken from a request header.
// A JWT-SVID is a bearer credential with no key to bind.
package spiffe
