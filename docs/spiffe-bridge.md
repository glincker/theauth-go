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

## Certificate bound access tokens

An agent or robot that proved itself with an X.509-SVID can trade it for an access token bound to that certificate (RFC 8705 section 3). The token carries `cnf` with `x5t#S256`, the SHA-256 thumbprint of the leaf certificate. `mcpresource` accepts it only on a TLS connection that presents that same certificate, so a copied token is useless without the private key.

```go
// Config.AuthorizationServer needs DeviceTokens, and the device must have the SPIFFE ID of the SVID.
res, serr := br.AuthenticateX509(ctx, r.TLS.PeerCertificates)
if serr != nil {
	http.Error(w, "unauthorized", http.StatusUnauthorized)
	return
}
tok, err := br.IssueToken(ctx, auth, res, "https://iot.example.com/api", []string{"telemetry:write"})
// tok.AccessToken is a Bearer token with cnf x5t#S256. tok.ExpiresIn never runs past the SVID.
```

`auth` is your `*theauth.TheAuth`. `IssueToken` calls `TheAuth.IssueDeviceCertToken`, which goes through the same token machinery as the device assertion grant: the device must be active, `resource` and `scope` are checked against the device's enrolled scopes and the resource's scopes, the per device token rate limit applies, `Config.OnTokenIssued` runs, and a `device.token_minted` audit row is written with `mtls_bound` true. The token lifetime is `DeviceTokensConfig.AccessTokenTTL` or the time left on the SVID, whichever is shorter. No refresh token is issued, because the SVID is the long lived credential and is renewed by SPIRE.

Rules that matter:

- Only an X.509-SVID result works. A JWT-SVID has no key the holder proves possession of, so `IssueToken` returns `ErrNoKeyBinding` for it.
- There is no HTTP route for this. The exchange trusts the caller to have verified the TLS handshake, so it is a Go call you make from your own mutual TLS endpoint, never a form field.
- The token is a plain `Bearer` token as far as the client is concerned (RFC 8705 does not change the token type). A resource server that does not enforce `cnf` would treat it as bearer, so use `mcpresource`, or check `cnf` yourself.
- The thumbprint is the one `mcpresource.CertThumbprint` computes. Behind a TLS terminating proxy, give the validator `mcpresource.WithClientCertThumbprint` and have the proxy set the header itself.

`iot/spiffe/token_test.go` runs the whole path with a real TLS server: an SVID is exchanged, the token works with the matching certificate, and it is refused for another valid SVID of the same workload (a different key) and for a connection with no certificate.

## Limits

- No name constraints. The standard library parses Ed25519 and PSS certificate signatures, which the TypeScript side refuses, so no shared vector covers them.
- The vectors are generated, not hand written: `node docs-local/vectors/gen-spiffe-vectors.mjs` (needs openssl and a built TypeScript core).
