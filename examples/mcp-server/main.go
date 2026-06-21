// Example MCP server using the mcpresource SDK. Demonstrates the one-import
// claim: a fresh MCP server gets RFC 9068 token validation, RFC 8693 chain
// walking, and RFC 9728 metadata pointers with a single import and a single
// middleware line.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/glincker/theauth-go/mcpresource"
	"github.com/go-chi/chi/v5"
)

func main() {
	resourceURI := envOr("MCP_RESOURCE", "https://mcp.example.com")
	jwksURI := envOr("MCP_JWKS_URI", "https://as.example.com/oauth/jwks")
	introspectURI := envOr("MCP_INTROSPECT_URI", "https://as.example.com/oauth/introspect")
	clientID := envOr("MCP_CLIENT_ID", "mcp-resource-client")
	clientSecret := envOr("MCP_CLIENT_SECRET", "change-me")

	v := mcpresource.New(
		resourceURI,
		mcpresource.WithJWKS(jwksURI),
		mcpresource.WithIntrospection(introspectURI, clientID, clientSecret),
	)

	r := chi.NewRouter()
	r.Use(v.Middleware)

	r.Get("/tools", func(w http.ResponseWriter, r *http.Request) {
		p, ok := v.Principal(r.Context())
		if !ok {
			http.Error(w, "no principal", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"subject":     p.Subject,
			"actor":       p.Actor,
			"actor_chain": p.ActorChain,
			"scope":       p.Scope,
		})
	})

	addr := envOr("MCP_LISTEN_ADDR", ":8090")
	log.Printf("mcp-server listening on %s (resource=%s)", addr, resourceURI)
	if err := http.ListenAndServe(addr, r); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}
