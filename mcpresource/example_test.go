package mcpresource_test

import (
	"fmt"
	"net/http"
	"slices"

	"github.com/glincker/theauth-go/mcpresource"
)

// ExampleValidator_Middleware validates a bearer, resolves the actor chain
// and checks a per-tool scope. Principal.ActorChain lists the agents between
// the human (Subject) and the caller (Actor), so log both.
func ExampleValidator_Middleware() {
	v := mcpresource.New(
		"https://mcp.example.com",
		mcpresource.WithJWKS("https://as.example.com/oauth/jwks"),
		mcpresource.WithIntrospection("https://as.example.com/oauth/introspect", "mcp-rs", "secret"),
	)
	toolScope := map[string]string{"logs.read": "logs:read", "deploy.create": "deploy:create"}

	mux := http.NewServeMux()
	mux.HandleFunc("/mcp/tools/", func(w http.ResponseWriter, r *http.Request) {
		p, ok := v.Principal(r.Context())
		if !ok {
			http.Error(w, "no principal", http.StatusUnauthorized)
			return
		}
		tool := r.URL.Path[len("/mcp/tools/"):]
		need, known := toolScope[tool]
		if !known || !slices.Contains(p.Scope, need) {
			http.Error(w, "tool not permitted", http.StatusForbidden)
			return
		}
		fmt.Fprintf(w, "%s acting for %s via %v", p.Actor, p.Subject, p.ActorChain)
	})
	_ = http.ListenAndServe(":8090", v.Middleware(mux))
}
