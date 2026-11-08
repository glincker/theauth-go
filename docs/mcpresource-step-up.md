# Step-up and sender constrained tokens on the resource server

The `mcpresource` package protects an MCP server or any Go API that accepts
OAuth access tokens from theAuth or another RFC 9068 authorization server. This
page covers three checks that go beyond signature and audience: step-up
authentication, DPoP proofs and mutual TLS certificate binding. The TypeScript
side is described in `step-up-auth.mdx` and `dpop-agent-tokens.mdx` in the SDK
docs, and the claims are the same.

## Step-up (RFC 9470)

A token carries `acr` (how strongly the user signed in) and `auth_time` (when).
`RequireStepUp` answers `401` with an `insufficient_user_authentication`
challenge when either is too weak or too old, so a client can send the user
through the authorization endpoint again with `acr_values` and `max_age`.

```go
v := mcpresource.New("https://mcp.example.com",
	mcpresource.WithJWKS("https://auth.example.com/.well-known/jwks.json"))

r := chi.NewRouter()
r.Use(v.Middleware)
r.With(v.RequireStepUp(mcpresource.StepUp{
	ACRValues: []string{mcpresource.ACRMFA},
	MaxAge:    5 * time.Minute,
})).Post("/tools/transfer", transfer)
```

A refused request gets:

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer error="insufficient_user_authentication", error_description="...",
  acr_values="urn:theauth:acr:mfa", max_age="300",
  resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource"
```

The same facts are in the JSON body under `step_up`. Rules:

- theAuth classes are ordered: `none`, `single-factor`, `mfa`, `phishing-resistant`
  (constants `ACRNone`, `ACRSingleFactor`, `ACRMFA`, `ACRPhishingResistant`). A stronger
  class satisfies a request for a weaker one. With several `ACRValues`, the weakest
  theAuth class listed is the bar.
- Any other `acr` string is opaque (RFC 9470 section 2) and matches only by equality.
  Use that for tokens from a different authorization server.
- A token without `acr`, such as one from the client credentials grant, never passes an
  `ACRValues` requirement. A token without `auth_time` never passes a `MaxAge`.
- An `auth_time` more than a minute ahead of the server clock is refused.
- The values describe the login that produced the token and do not change while it lives.
  Resource servers set `MaxAge`, and clients get a fresh token by going through authorize.

## DPoP (RFC 9449)

When the token's `cnf` has `jkt`, the request must use `Authorization: DPoP <token>`
and a `DPoP` header whose proof was signed by the key with that thumbprint. Enable the
verifier once:

```go
v := mcpresource.New("https://mcp.example.com",
	mcpresource.WithJWKS(jwksURL),
	mcpresource.WithDPoPVerification(nil, 0, 0), // default algs, 60s window, 4096 jtis
)
```

The verifier checks `typ`, the algorithm allow list, the signature, `htm`, `htu`
(query and fragment ignored), `iat` inside the window, a unique `jti`, `ath` against the
access token and the key thumbprint against `cnf.jkt`. Opaque tokens go through
introspection and are held to the same `cnf.jkt` rule.

Failures answer `401` with the DPoP scheme and the code from RFC 9449 section 7.1:
`invalid_dpop_proof` for a bad proof, `invalid_token` for a missing header or a key that
is not the bound one, plus an `algs` parameter listing accepted algorithms.

### Server nonces

Nonces stop a stolen key from pre-signing proofs with a future `iat`:

```go
mcpresource.WithDPoPNonce([]byte(os.Getenv("DPOP_NONCE_SECRET")), 5*time.Minute)
```

A proof without a current nonce gets `WWW-Authenticate: DPoP error="use_dpop_nonce"` and a
`DPoP-Nonce` header (section 9); the client retries with the nonce in the proof. Successful
responses carry the next nonce. Nonces are an HMAC over a time window, so no storage is
needed, and instances that share the secret accept each other's nonces. A nonce lives
between one and two windows.

### Replay cache across instances

The default `jti` cache is in memory per validator. Behind a load balancer, give every
instance the same one:

```go
type redisReplay struct{ rdb *redis.Client }

func (c redisReplay) Remember(jti string, expiresAt time.Time) bool {
	ok, err := c.rdb.SetNX(ctx, "dpop:"+jti, 1, time.Until(expiresAt)).Result()
	return err == nil && ok // fail closed: an error rejects the proof
}

mcpresource.WithDPoPReplayCache(redisReplay{rdb})
```

## Mutual TLS (RFC 8705)

When `cnf` has `x5t#S256`, the request must present the client certificate whose DER
SHA-256 thumbprint (base64url, no padding) matches. By default the validator reads the leaf
certificate of the TLS connection, so the server must run with `ClientAuth` set to
`tls.RequireAnyClientCert` or stricter. Where TLS ends at a proxy, tell the validator how to
get the thumbprint of the certificate the proxy verified:

```go
mcpresource.WithClientCertThumbprint(func(r *http.Request) string {
	return r.Header.Get("X-Client-Cert-Sha256")
})
```

Only trust a header your proxy sets itself and strips from inbound traffic. A token bound by
certificate and no certificate is always refused. `mcpresource.CertThumbprint(cert)` computes
the value, for the authorization server side or tests.

A token bound to both `jkt` and `x5t#S256` needs the proof and the certificate. The
`Principal` exposes `CnfJKT` and `CnfX5tS256` only after the match succeeded.

## Tests and vectors

`mcpresource/stepup_cnf_test.go` runs the RFC 9449 Figure 13 resource request (token, proof and
`jkt` verbatim) through the verifier, and the RFC 7638 section 3.1 thumbprint example. RFC 8705
publishes no certificate vector, so the mTLS tests generate a certificate and check the
thumbprint against `sha256(cert.Raw)` directly.
