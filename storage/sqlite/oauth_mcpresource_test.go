package sqlite_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/glincker/theauth-go/mcpresource"
	"github.com/glincker/theauth-go/v2"
)

// TestMCPResourceServerE2E exercises the mcpresource middleware against a live SQLite-backed AS:
// JWKS validation, RFC 9728 challenges, scopes, audience, and revocation via RevocationChecker.
// Tokens with act or delegation_grant_id are always rechecked through introspection.
func TestMCPResourceServerE2E(t *testing.T) {
	e := newOAuthEnv(t)
	ctx := context.Background()
	user, cookie := e.signIn("mcp-rs@levelrail.test")
	clientID := e.registerNative()
	rsID, rsSecret := e.registerConfidential("levelrail-mcp-rs", []string{"authorization_code"})

	const cacheTTL = 20 * time.Millisecond

	// mkRS builds an httptest resource server guarded by a validator.
	mkRS := func(t *testing.T, resource string, opts ...mcpresource.Option) (*mcpresource.Validator, *httptest.Server) {
		t.Helper()
		base := []mcpresource.Option{
			mcpresource.WithJWKS(e.srv.URL + "/oauth/jwks"),
			mcpresource.WithIntrospection(e.srv.URL+"/oauth/introspect", rsID, rsSecret),
			mcpresource.WithCacheTTL(cacheTTL),
		}
		v := mcpresource.New(resource, append(base, opts...)...)
		mux := http.NewServeMux()
		mux.Handle("/mcp", v.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, ok := v.Principal(r.Context())
			if !ok {
				http.Error(w, "no principal", http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"sub": p.Subject, "actor": p.Actor, "chain": p.ActorChain, "scope": p.Scope, "aud": p.Audience,
			})
		})))
		mux.Handle("/write", v.Middleware(v.RequireScope(oaScopeWrit)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))))
		rs := httptest.NewServer(mux)
		t.Cleanup(rs.Close)
		return v, rs
	}
	call := func(t *testing.T, rs *httptest.Server, path, token string) (int, http.Header, map[string]any) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, rs.URL+path, nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		res, err := e.hc.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = res.Body.Close() }()
		var out map[string]any
		_ = json.NewDecoder(res.Body).Decode(&out)
		return res.StatusCode, res.Header, out
	}
	wantMeta := "resource_metadata=\"https://mcp.levelrail.test/.well-known/oauth-protected-resource/mcp\""

	_, rs := mkRS(t, oaResource)

	t.Run("NoTokenChallenge", func(t *testing.T) {
		status, hdr, body := call(t, rs, "/mcp", "")
		if status != http.StatusUnauthorized {
			t.Fatalf("status %d, want 401", status)
		}
		wa := hdr.Get("WWW-Authenticate")
		if !strings.HasPrefix(wa, "Bearer ") || !strings.Contains(wa, wantMeta) {
			t.Fatalf("WWW-Authenticate = %q, want Bearer with %s (RFC 9728)", wa, wantMeta)
		}
		if body["error"] != "invalid_token" {
			t.Fatalf("body = %v", body)
		}
		if status, _, _ := call(t, rs, "/mcp", "not.a.jwt"); status != http.StatusUnauthorized {
			t.Fatalf("garbage token status %d, want 401", status)
		}
	})

	var at, rt string
	t.Run("ValidAccessTokenAndPrincipal", func(t *testing.T) {
		tok := e.tokensFor(clientID, cookie)
		at, rt = tok.str("access_token"), tok.str("refresh_token")
		status, _, body := call(t, rs, "/mcp", at)
		if status != http.StatusOK {
			t.Fatalf("status %d body %v", status, body)
		}
		if body["sub"] != user.ID.String() {
			t.Fatalf("sub = %v, want %s", body["sub"], user.ID)
		}
		scopes, _ := body["scope"].([]any)
		if len(scopes) != 1 || scopes[0] != oaScopeRead {
			t.Fatalf("scope = %v, want [%s]", body["scope"], oaScopeRead)
		}
		if body["aud"] != oaResource {
			t.Fatalf("aud = %v", body["aud"])
		}
	})

	t.Run("InsufficientScope", func(t *testing.T) {
		status, hdr, body := call(t, rs, "/write", at)
		if status != http.StatusForbidden || body["error"] != "insufficient_scope" {
			t.Fatalf("got %d %v, want 403 insufficient_scope", status, body)
		}
		wa := hdr.Get("WWW-Authenticate")
		if !strings.Contains(wa, `error="insufficient_scope"`) || !strings.Contains(wa, `scope="`+oaScopeWrit+`"`) {
			t.Fatalf("WWW-Authenticate = %q", wa)
		}
	})

	t.Run("WrongAudience", func(t *testing.T) {
		_, other := mkRS(t, "https://other.levelrail.test/mcp")
		status, hdr, _ := call(t, other, "/mcp", at)
		if status != http.StatusUnauthorized {
			t.Fatalf("token for %s accepted by another resource: %d", oaResource, status)
		}
		if !strings.Contains(hdr.Get("WWW-Authenticate"), "invalid_token") {
			t.Fatalf("WWW-Authenticate = %q", hdr.Get("WWW-Authenticate"))
		}
	})

	t.Run("RevocationVisibility", func(t *testing.T) {
		// A second validator with a RevocationChecker that asks the AS.
		_, checked := mkRS(t, oaResource, mcpresource.WithRevocationChecker(
			mcpresource.RevocationCheckerFunc(func(_ context.Context, token string, _ *mcpresource.Principal) (bool, error) {
				return !active(e.introspect(rsID, rsSecret, token)), nil
			})))
		if status, _, body := call(t, checked, "/mcp", at); status != http.StatusOK {
			t.Fatalf("before revoke: %d %v", status, body)
		}
		status, out := e.postForm("/oauth/revoke", url.Values{"token": {at}, "token_type_hint": {"access_token"}, "client_id": {clientID}}, "", "")
		if status != http.StatusOK {
			t.Fatalf("revoke: %d %v", status, out)
		}
		if active(e.introspect(rsID, rsSecret, at)) {
			t.Fatal("AS still reports the revoked token active")
		}
		if status, _, body := call(t, checked, "/mcp", at); status != http.StatusUnauthorized || body["error"] != "invalid_token" {
			t.Fatalf("revoked token with RevocationChecker: %d %v, want 401", status, body)
		}
		// JWKS-only validation is offline: it cannot see the revocation.
		if status, _, _ := call(t, rs, "/mcp", at); status != http.StatusOK {
			t.Fatalf("JWKS-only validator after revoke: %d, documents offline validation as blind to revocation", status)
		}
		_ = rt
	})

	t.Run("AgentActChainAndGrantRevocation", func(t *testing.T) {
		userTok := e.tokensFor(clientID, cookie)
		uid := user.ID
		agent, secret, err := e.a.CreateAgent(ctx, theauth.CreateAgentInput{
			Owner: theauth.AgentOwner{UserID: &uid},
			Name:  "levelrail-mcp-agent",
			Scope: []string{oaScopeRead, oaScopeWrit},
		})
		if err != nil {
			t.Fatalf("CreateAgent: %v", err)
		}
		grant, err := e.a.GrantDelegation(ctx, theauth.GrantDelegationInput{
			UserID: user.ID, AgentID: agent.ID, Scope: []string{oaScopeRead},
			Resource: oaResource, MaxDurationSeconds: 1800,
		})
		if err != nil {
			t.Fatalf("GrantDelegation: %v", err)
		}
		status, ex := e.postForm("/oauth/token", url.Values{
			"grant_type":           {"urn:ietf:params:oauth:grant-type:token-exchange"},
			"subject_token":        {userTok.str("access_token")},
			"subject_token_type":   {"urn:ietf:params:oauth:token-type:access_token"},
			"requested_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
			"resource":             {oaResource},
			"scope":                {oaScopeRead},
		}, secret.ClientID, secret.Secret)
		if status != http.StatusOK {
			t.Fatalf("token exchange: %d %v", status, ex)
		}
		agentTok := ex.str("access_token")

		st, _, body := call(t, rs, "/mcp", agentTok)
		if st != http.StatusOK {
			t.Fatalf("delegated token rejected: %d %v", st, body)
		}
		wantActor := theauth.AgentSubjectPrefix + agent.ID.String()
		chain, _ := body["chain"].([]any)
		if body["sub"] != user.ID.String() || body["actor"] != wantActor || len(chain) != 1 {
			t.Fatalf("principal = %v, want sub %s actor %s", body, user.ID, wantActor)
		}

		if err := e.a.RevokeDelegation(ctx, grant.ID, "mcpresource e2e"); err != nil {
			t.Fatalf("RevokeDelegation: %v", err)
		}
		// The AS caches chain results for IntrospectionCacheTTL (1s here), so wait that out.
		e.clock.Advance(time.Hour)
		time.Sleep(1200 * time.Millisecond)
		st, hdr, body := call(t, rs, "/mcp", agentTok)
		if st != http.StatusUnauthorized || body["error"] != "invalid_token" {
			t.Fatalf("after grant revoke: %d %v, want 401 invalid_token", st, body)
		}
		if !strings.Contains(hdr.Get("WWW-Authenticate"), wantMeta) {
			t.Fatalf("WWW-Authenticate = %q", hdr.Get("WWW-Authenticate"))
		}
	})
}
