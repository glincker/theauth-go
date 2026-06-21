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
// The package validates the JWT signature against a cached JWKS, enforces the
// audience claim against the configured resource URI, checks expiry with a
// small skew tolerance, and walks the RFC 8693 actor chain via the AS
// introspection endpoint so revocations propagate inside WithCacheTTL.
//
// This package is intentionally a standalone Go module with zero
// dependencies outside the standard library. A consumer importing it does
// not transitively pull in theauth core, the storage adapters, or any other
// theauth-go package.
package mcpresource
