package theauth_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/internal/ulid"
	"github.com/glincker/theauth-go/storage/memory"
	"github.com/go-chi/chi/v5"
)

// toolAbility maps each MCP tool to the ability a caller needs for it.
var toolAbility = map[string]string{
	"logs.read":     "logs:read",
	"deploy.create": "deploy:create",
}

// requireTool checks the per-tool ability on the resolved principal and
// reports who acted, human first and agent second.
func requireTool(next func(w http.ResponseWriter, r *http.Request, who string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := theauth.PrincipalFromContext(r.Context())
		if !ok {
			http.Error(w, "no principal", http.StatusUnauthorized)
			return
		}
		need, known := toolAbility[r.URL.Query().Get("tool")]
		if !known || !p.Has(need) {
			http.Error(w, "tool not permitted", http.StatusForbidden)
			return
		}
		var names []string
		for _, actor := range p.ActorChain() {
			names = append(names, actor.Kind)
		}
		next(w, r, strings.Join(names, ">"))
	}
}

// ExampleTheAuth_MintAgentToken runs a Go MCP-style tool endpoint behind an
// agent token: RequireAbility validates the bearer and re-evaluates the
// owner's abilities on every call, requireTool gates each tool, and
// WatchRevocationMiddleware drops the request when the credential is revoked.
func ExampleTheAuth_MintAgentToken() {
	ctx := context.Background()
	store := memory.New()
	var userHas = []string{"logs:read", "deploy:create"}
	a, err := theauth.New(theauth.Config{
		Storage: store, BaseURL: "http://localhost", SessionTTL: time.Hour, MagicLinkTTL: time.Minute,
		APITokens: &theauth.APITokensConfig{
			UserAbilities: func(context.Context, *theauth.User) ([]string, error) { return userHas, nil },
		},
	})
	if err != nil {
		panic(err)
	}
	defer a.Close()

	owner, _ := store.CreateUser(ctx, theauth.User{ID: ulid.New(), Email: "dev@example.com", CreatedAt: time.Now(), UpdatedAt: time.Now()})
	secret, _, err := a.MintAgentToken(ctx, theauth.MintAgentTokenInput{
		UserID: owner.ID, AgentName: "claude-desktop", Abilities: []string{"logs:read", "deploy:create"},
	})
	if err != nil {
		panic(err)
	}

	r := chi.NewRouter()
	r.Group(func(r chi.Router) {
		r.Use(a.RequireAbility("logs:read"), a.WatchRevocationMiddleware(theauth.WatchOptions{PollInterval: 5 * time.Second}))
		r.Get("/mcp", requireTool(func(w http.ResponseWriter, _ *http.Request, who string) {
			_, _ = fmt.Fprint(w, "ok acting as ", who)
		}))
	})
	srv := httptest.NewServer(r)
	defer srv.Close()

	call := func(tool string) {
		req, _ := http.NewRequest("GET", srv.URL+"/mcp?tool="+tool, nil)
		req.Header.Set("Authorization", "Bearer "+secret)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			panic(err)
		}
		defer func() { _ = resp.Body.Close() }()
		fmt.Println(tool, resp.StatusCode)
	}
	call("logs.read")
	call("deploy.create")
	userHas = []string{"logs:read"}
	call("deploy.create")
	// Output:
	// logs.read 200
	// deploy.create 200
	// deploy.create 403
}
