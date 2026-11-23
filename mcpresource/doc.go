// Package mcpresource is the one-import resource server SDK for MCP servers
// that trust a theauth-go (or any RFC 9068 + RFC 9728) authorization server.
//
// An MCP server author wires the middleware once:
//
//	v := mcpresource.New(
//	    "https://mcp.example.com",
//	    mcpresource.WithJWKS("https://as.example.com/oauth/jwks"),
//	    mcpresource.WithIntrospection(
//	        "https://as.example.com/oauth/introspect",
//	        "mcp-client-id",
//	        "mcp-client-secret",
//	    ),
//	)
//	r := chi.NewRouter()
//	r.Use(v.Middleware)
//	r.Get("/tools/run", func(w http.ResponseWriter, r *http.Request) {
//	    p, _ := v.Principal(r.Context())
//	    // p.Subject is the user, p.Actor is the final agent, p.ActorChain
//	    // walks innermost (delegated agent) to outermost (root).
//	})
//
// Access tokens may be signed with EdDSA, ES256 or RS256 (RSA >= 2048 bits);
// aud may be a string or an array. RequireScope and RequireStepUp add
// per-route scope (RFC 6750) and step-up (RFC 9470) challenges, ToolSecurity
// builds tools/list security metadata, and NewURLElicitation builds MCP URL
// mode elicitations.
//
// Sender constrained tokens: a token whose cnf claim carries jkt needs a DPoP
// proof (RFC 9449, with WithDPoPVerification, optional server nonces through
// WithDPoPNonce and a shared replay cache through WithDPoPReplayCache). A token
// whose cnf carries x5t#S256 needs the matching client certificate (RFC 8705,
// see WithClientCertThumbprint for TLS terminating proxies). Both members are
// enforced when both are present, for JWTs and introspected opaque tokens.
//
// A RevocationChecker (WithRevocationChecker) lets a server that validates
// JWTs locally consult a denylist or the AS for tokens revoked before exp;
// WithDeviceRevocationIntrospection does that for device tokens through the
// introspection endpoint.
//
// The package validates the JWT signature against a cached JWKS, enforces the
// audience claim against the configured resource URI and checks expiry with a
// small skew tolerance. Only tokens that carry an act claim or a
// delegation_grant_id are rechecked against the AS introspection endpoint
// (RFC 7662), so a revoked delegation is seen within WithCacheTTL (or the AS
// Cache-Control max-age). Other JWTs are validated offline.
//
// WithOpaqueTokens adds support for opaque (reference) access tokens: tokens
// that are not JWT shaped are introspected, and the Principal is built from
// the introspection response with the same audience, expiry and DPoP checks.
//
// This package is intentionally a standalone Go module with zero
// dependencies outside the standard library. A consumer importing it does
// not transitively pull in theauth core, the storage adapters, or any other
// theauth-go package.
package mcpresource
