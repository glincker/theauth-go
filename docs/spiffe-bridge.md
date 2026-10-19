# SPIFFE workload identity bridge

`iot/spiffe` lets a workload or robot that already holds a SPIFFE SVID act as a theAuth device. It verifies an X.509-SVID or a JWT-SVID against a trust bundle you configure and maps the SPIFFE ID to a registered device with `Storage.DeviceBySPIFFEID`. It is the Go twin of the TypeScript bridge in `@glinr/theauth` (`sdk/packages/core/src/device/spiffe`) and replays the same test vectors, so both sides give the same refusal code for every case.

Nothing is created on the fly. A SPIFFE ID that no device carries is refused. The SPIFFE ID of a device is fixed by the operator when the device is enrolled (a join token carries it), so a device cannot claim someone else's identity.

## Use it

```go
br, err := spiffe.New(spiffe.Config{
	TrustDomains: map[string]spiffe.TrustDomainConfig{
		"example.org": {Endpoint: &spiffe.Endpoint{URL: "https://spire.example.org/bundle"}},
	},
	Audience: []string{"https://theauth.example.org"},
	Devices:  store, // any theauth.DeviceIdentityStorage
})
if err != nil {
	log.Fatal(err) // a typo in a trust domain is found at startup
}

// X.509-SVID: pass the chain from a TLS handshake your server verified.
res, serr := br.AuthenticateX509(ctx, r.TLS.PeerCertificates)
if serr != nil {
	// serr.Code is stable (see the constants), serr.Reason is for logs only.
	http.Error(w, "unauthorized", http.StatusUnauthorized)
	return
}
// res.Device is the device, res.CNF["x5t#S256"] the RFC 8705 confirmation of the certificate.

// JWT-SVID: a bearer credential, audience checked, expiry at most one hour ahead.
res, serr = br.AuthenticateJWT(ctx, bearerToken)
```

The caller must already know the peer holds the leaf key. Take the certificate from `tls.ConnectionState.PeerCertificates` after the handshake, never from a header the client can set.

## Rules

They follow SPIFFE-ID.md, X509-SVID.md, JWT-SVID.md and the trust domain and bundle document.

X.509-SVID: exactly one URI SAN that is a valid SPIFFE ID with a path, cA false, key usage present and critical with `digitalSignature` and neither `keyCertSign` nor `cRLSign`, extended key usage (if present) allowing `clientAuth`, no unknown critical extension, an empty Subject only with a critical SAN, validity with 30 seconds of skew, and a chain that verifies up to a CA of the leaf's own trust domain with every issuer a CA that may sign certificates and respects `pathLenConstraint`.

JWT-SVID: algorithm in RS, ES or PS 256/384/512, headers only `alg`, `kid` and `typ` (`JWT` or `JOSE`), `kid` present, `sub` a SPIFFE ID with a path, `aud` containing one of your audiences, `exp` present and at most `MaxJWTTTL` ahead, signature from a `jwt-svid` key of the trust domain named by `sub`.

Bundles: static `Bundle` JSON, PEM `Roots`, or an `Endpoint` refreshed lazily when `spiffe_refresh_hint` has passed (no goroutine). The URL must be https, redirects are refused, the body is capped, polling is never faster than `MinRefresh`, a `spiffe_sequence` that goes backwards is refused, and a bundle older than `MaxStale` stops being trusted. An `https_spiffe` endpoint needs your own `http.Client` doing mutual TLS.

## Limits

- No name constraints. The standard library parses Ed25519 and PSS certificate signatures, which the TypeScript side refuses, so no shared vector covers them.
- Go does not mint an access token with `cnf` `x5t#S256` yet. `Result.CNF` carries the member, and `mcpresource` already enforces it on the resource side. Wiring it into the authorization server token endpoint is a follow up.
- The vectors are generated, not hand written: `node docs-local/vectors/gen-spiffe-vectors.mjs` (needs openssl and a built TypeScript core).
