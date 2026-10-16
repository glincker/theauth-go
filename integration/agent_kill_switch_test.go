package integration

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/internal/ulid"
	"github.com/glincker/theauth-go/v2/storage/memory"
	"github.com/go-chi/chi/v5"
)

const killSwitchResource = "https://mcp.example.com"

// TestAgentRevokeKillSwitch proves that suspending or revoking an agent cuts
// every credential bound to it at once: the API tokens minted for it, the
// OAuth self token on the introspection path (primed in the cache first), and
// streams scoped to its delegation grant.
func TestAgentRevokeKillSwitch(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		kill func(a *theauth.TheAuth, id theauth.ULID) error
	}{
		{"suspend", func(a *theauth.TheAuth, id theauth.ULID) error { return a.SuspendAgent(ctx, id, "incident") }},
		{"revoke", func(a *theauth.TheAuth, id theauth.ULID) error { return a.RevokeAgent(ctx, id, "incident") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := memory.New()
			a, err := theauth.New(theauth.Config{
				Storage: store, BaseURL: "http://localhost", SessionTTL: time.Hour, MagicLinkTTL: time.Minute,
				EncryptionKey: bytes.Repeat([]byte{7}, 32),
				APITokens: &theauth.APITokensConfig{
					Prefix: "tk",
					UserAbilities: func(context.Context, *theauth.User) ([]string, error) {
						return []string{"read"}, nil
					},
				},
				AuthorizationServer: &theauth.AuthorizationServerConfig{
					Issuer:          "https://auth.example.com",
					Resources:       []theauth.ProtectedResource{{Identifier: killSwitchResource, Scopes: []string{"read"}}},
					DisableRotation: true,
				},
				AgentIdentity: &theauth.AgentConfig{},
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(a.Close)
			u, _ := store.CreateUser(ctx, theauth.User{ID: ulid.New(), Email: "ks@x.test", CreatedAt: time.Now(), UpdatedAt: time.Now()})
			reg, err := a.RegisterAgent(ctx, theauth.RegisterAgentInput{OwnerID: u.ID, Name: "mcp", Scope: []string{"read"}, Resource: killSwitchResource})
			if err != nil {
				t.Fatal(err)
			}
			rawBound, bound, err := a.MintAgentToken(ctx, theauth.MintAgentTokenInput{UserID: u.ID, AgentName: "mcp", Abilities: []string{"read"}})
			if err != nil {
				t.Fatal(err)
			}
			rawOther, _, err := a.MintAgentToken(ctx, theauth.MintAgentTokenInput{UserID: u.ID, AgentName: "other-agent", Abilities: []string{"read"}})
			if err != nil {
				t.Fatal(err)
			}

			r := chi.NewRouter()
			r.With(a.RequireAbility("read")).Get("/r", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
			srv := httptest.NewServer(r)
			t.Cleanup(srv.Close)
			status := func(raw string) int {
				req, _ := http.NewRequest(http.MethodGet, srv.URL+"/r", nil)
				req.Header.Set("Authorization", "Bearer "+raw)
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				_ = resp.Body.Close()
				return resp.StatusCode
			}

			self, err := a.ClientCredentialsToken(ctx, theauth.TokenRequest{
				GrantType: theauth.GrantTypeClientCredentials, ClientID: reg.Secret.ClientID,
				ClientSecret: reg.Secret.Secret, Resource: killSwitchResource, Scope: []string{"read"},
			})
			if err != nil {
				t.Fatal(err)
			}
			introspect := func() bool {
				resp, _, err := a.IntrospectToken(ctx, self.AccessToken, reg.Secret.ClientID, reg.Secret.Secret, killSwitchResource)
				if err != nil {
					t.Fatal(err)
				}
				return resp.Active
			}
			wctx, cancel := a.WatchRevocation(ctx, theauth.RevocationTarget{DelegationID: reg.Grant.ID.String()}, theauth.WatchOptions{})
			defer cancel(nil)
			tctx, tcancel := a.WatchRevocation(ctx, theauth.RevocationTarget{TokenID: bound.ID.String()}, theauth.WatchOptions{})
			defer tcancel(nil)

			if status(rawBound) != http.StatusOK || status(rawOther) != http.StatusOK {
				t.Fatal("tokens must work before the kill switch")
			}
			if !introspect() {
				t.Fatal("agent self token must introspect active before the kill switch")
			}
			// The second call is served from the introspection cache, which is
			// what the kill switch has to invalidate.
			if !introspect() {
				t.Fatal("agent self token must stay active on a cache hit before the kill switch")
			}

			if err := tc.kill(a, reg.Agent.ID); err != nil {
				t.Fatal(err)
			}

			if got := status(rawBound); got != http.StatusUnauthorized {
				t.Fatalf("minted agent token after kill: status %d, want 401", got)
			}
			if got := status(rawOther); got != http.StatusOK {
				t.Fatalf("token of an unrelated agent was cut: status %d", got)
			}
			if introspect() {
				t.Fatal("agent self token still active on introspection right after kill")
			}
			for name, c := range map[string]context.Context{"delegation stream": wctx, "api token stream": tctx} {
				select {
				case <-c.Done():
				case <-time.After(time.Second):
					t.Fatalf("%s not cut by agent kill", name)
				}
			}
		})
	}
}

// TestAgentRevokeCascadeMatchesByAgentID proves the cascade cuts minted tokens
// by agent id: two organization owned agents share a name, revoking one leaves
// the other's token valid, and a legacy token with no agent id is still cut by
// the name fallback.
func TestAgentRevokeCascadeMatchesByAgentID(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	a, err := theauth.New(theauth.Config{
		Storage: store, BaseURL: "http://localhost", SessionTTL: time.Hour, MagicLinkTTL: time.Minute,
		EncryptionKey: bytes.Repeat([]byte{7}, 32),
		APITokens: &theauth.APITokensConfig{
			Prefix: "tk",
			UserAbilities: func(context.Context, *theauth.User) ([]string, error) {
				return []string{"read"}, nil
			},
		},
		AuthorizationServer: &theauth.AuthorizationServerConfig{
			Issuer:          "https://auth.example.com",
			Resources:       []theauth.ProtectedResource{{Identifier: killSwitchResource, Scopes: []string{"read"}}},
			DisableRotation: true,
		},
		AgentIdentity: &theauth.AgentConfig{},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)

	mkUser := func(email string) theauth.User {
		u, err := store.CreateUser(ctx, theauth.User{ID: ulid.New(), Email: email, CreatedAt: time.Now(), UpdatedAt: time.Now()})
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	org := ulid.New()
	mkAgent := func() theauth.Agent {
		ag, _, err := a.CreateAgent(ctx, theauth.CreateAgentInput{
			Owner: theauth.AgentOwner{OrganizationID: &org}, Name: "triage", Scope: []string{"read"},
		})
		if err != nil {
			t.Fatal(err)
		}
		return ag
	}
	agentA, agentB := mkAgent(), mkAgent()
	mint := func(u theauth.User, agentID *theauth.ULID) string {
		raw, _, err := a.MintAgentToken(ctx, theauth.MintAgentTokenInput{
			UserID: u.ID, AgentName: "triage", AgentID: agentID, Abilities: []string{"read"},
		})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	rawA := mint(mkUser("a@x.test"), &agentA.ID)
	rawB := mint(mkUser("b@x.test"), &agentB.ID)
	rawLegacy := mint(mkUser("legacy@x.test"), nil)

	r := chi.NewRouter()
	r.With(a.RequireAbility("read")).Get("/r", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	status := func(raw string) int {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/r", nil)
		req.Header.Set("Authorization", "Bearer "+raw)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	for name, raw := range map[string]string{"A": rawA, "B": rawB, "legacy": rawLegacy} {
		if got := status(raw); got != http.StatusOK {
			t.Fatalf("token %s before revoke: status %d", name, got)
		}
	}

	if err := a.RevokeAgent(ctx, agentA.ID, "incident"); err != nil {
		t.Fatal(err)
	}
	if got := status(rawA); got != http.StatusUnauthorized {
		t.Fatalf("revoked agent token: status %d, want 401", got)
	}
	if got := status(rawB); got != http.StatusOK {
		t.Fatalf("same named agent with its own id was over-revoked: status %d", got)
	}
	if got := status(rawLegacy); got != http.StatusUnauthorized {
		t.Fatalf("legacy token without agent id must be cut by the name fallback: status %d", got)
	}
}
