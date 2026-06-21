package theauth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/crypto"
	"github.com/glincker/theauth-go/internal/ulid"
	"github.com/glincker/theauth-go/mcpresource"
	"github.com/go-chi/chi/v5"
)

// e2e_as_validator_test.go closes the headline gap from the 2026-06-20
// reliability audit (section 4, scenario E2E-1):
//
//	"Today the AS-side delegation exchange is tested in isolation against
//	 the AS's own introspection cache; the mcpresource validator is tested
//	 in isolation against a hand-rolled fake AS that returns canned JWKS +
//	 introspection. No single test wires the real AS, mints a real
//	 delegated JWT, and validates it through the real mcpresource
//	 middleware. A serialization mismatch between the AS's act chain shape
//	 and the validator's parser would not be caught."
//
// This test stands up the real authorisation server via httptest.NewServer,
// performs a real user login (StartAuthorize + ExchangeAuthorizationCode),
// registers a real agent, performs a real RFC 8693 token exchange, then
// validates the resulting JWT through a real mcpresource.Validator pointed
// at the AS's own JWKS + introspection endpoints. A wire-format mismatch
// between the AS-side serialization and the validator-side parser would
// fail the principal assertion.
func TestUserLoginAgentExchangeMcpresourceValidate(t *testing.T) {
	// 1. Stand up the AS with agent identity enabled and host it via httptest.
	a, store := newAgentASInstance(t)
	user := theauth.User{ID: ulid.New(), Email: "alice@example.com"}
	if _, err := store.CreateUser(context.Background(), user); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	r := chi.NewRouter()
	a.Mount(r)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)

	// 2. Real user login: register a confidential client and exchange a code
	// for a user-rooted access token (the subject token for step 5).
	userClient := registerTestClient(t, srv)
	verifier, _ := crypto.NewCodeVerifier()
	authzReq := theauth.AuthorizeRequest{
		ClientID:            userClient.ClientID,
		RedirectURI:         "https://app.example.com/cb",
		ResponseType:        "code",
		Scope:               []string{"files.read", "files.write"},
		CodeChallenge:       crypto.CodeChallenge(verifier),
		CodeChallengeMethod: "S256",
		Resource:            "https://files.example.com/mcp",
	}
	ctx := context.Background()
	res, err := a.StartAuthorize(ctx, authzReq, &user)
	if err != nil {
		t.Fatalf("StartAuthorize: %v", err)
	}
	code := codeFromRedirect(t, res.RedirectURL)
	userTok, err := a.ExchangeAuthorizationCode(ctx, theauth.TokenRequest{
		GrantType:    theauth.GrantTypeAuthorizationCode,
		ClientID:     userClient.ClientID,
		ClientSecret: userClient.ClientSecret,
		Code:         code,
		CodeVerifier: verifier,
		RedirectURI:  "https://app.example.com/cb",
	})
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode: %v", err)
	}

	// 3. Real agent registration owned by the user.
	uid := user.ID
	agent, agentSecret, err := a.CreateAgent(ctx, theauth.CreateAgentInput{
		Owner: theauth.AgentOwner{UserID: &uid},
		Name:  "e2e-agent",
		Scope: []string{"files.read", "files.write"},
	})
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}

	// 4. Real delegation grant from the user to the agent.
	grant, err := a.GrantDelegation(ctx, theauth.GrantDelegationInput{
		UserID:             user.ID,
		AgentID:            agent.ID,
		Scope:              []string{"files.read"},
		Resource:           "https://files.example.com/mcp",
		MaxDurationSeconds: 1800,
	})
	if err != nil {
		t.Fatalf("GrantDelegation: %v", err)
	}

	// 5. Real RFC 8693 token exchange: the agent presents the user's access
	// token as subject_token and gets back a delegated JWT naming the user
	// as sub and the agent as the innermost actor.
	exchanged, err := a.ExchangeToken(ctx, theauth.TokenExchangeRequest{
		ClientID:         agentSecret.ClientID,
		ClientSecret:     agentSecret.Secret,
		SubjectToken:     userTok.AccessToken,
		SubjectTokenType: theauth.TokenTypeAccessToken,
		Resource:         "https://files.example.com/mcp",
		Scope:            []string{"files.read"},
	})
	if err != nil {
		t.Fatalf("ExchangeToken: %v", err)
	}

	// 6. Build the mcpresource.Validator against the real AS endpoints.
	// httptest.Server hosts the chi router, which includes /oauth/jwks and
	// /oauth/introspect. The validator MUST be able to fetch the same JWKS
	// the AS used to sign exchanged.AccessToken, and the introspection call
	// MUST authenticate through the agent's client credentials.
	v := mcpresource.New(
		"https://files.example.com/mcp",
		mcpresource.WithJWKS(srv.URL+"/oauth/jwks"),
		mcpresource.WithIntrospection(srv.URL+"/oauth/introspect", agentSecret.ClientID, agentSecret.Secret),
		mcpresource.WithCacheTTL(5*time.Second),
	)

	// 7. Wire the middleware around a no-op handler that asserts on the
	// extracted Principal. The middleware MUST validate signature, audience,
	// expiry, then walk the chain by calling /oauth/introspect on the AS.
	var captured *mcpresource.Principal
	handler := v.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := v.Principal(r.Context())
		if !ok {
			http.Error(w, "no principal", http.StatusInternalServerError)
			return
		}
		captured = p
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://files.example.com/mcp/tool", nil)
	req.Header.Set("Authorization", "Bearer "+exchanged.AccessToken)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s headers=%v", rec.Code, rec.Body.String(), rec.Header())
	}
	if captured == nil {
		t.Fatal("middleware did not attach principal to context")
	}

	// 8. Wire-format agreement assertions: every field the AS minted MUST
	// round-trip through the validator unchanged. A serialization mismatch
	// between actorClaimToMap on the AS side and flattenChain on the
	// validator side would surface here.
	if captured.Subject != user.ID.String() {
		t.Errorf("subject=%q, want user ULID %q", captured.Subject, user.ID.String())
	}
	wantActor := theauth.AgentSubjectPrefix + agent.ID.String()
	if captured.Actor != wantActor {
		t.Errorf("actor=%q, want %q", captured.Actor, wantActor)
	}
	if len(captured.ActorChain) != 1 || captured.ActorChain[0] != wantActor {
		t.Errorf("actor_chain=%v, want [%q]", captured.ActorChain, wantActor)
	}
	if captured.DelegationGrantID != grant.ID.String() {
		t.Errorf("delegation_grant_id=%q, want %q", captured.DelegationGrantID, grant.ID.String())
	}
	if captured.Audience != "https://files.example.com/mcp" {
		t.Errorf("audience=%q, want resource identifier", captured.Audience)
	}
	if captured.ClientID != agentSecret.ClientID {
		t.Errorf("client_id=%q, want %q", captured.ClientID, agentSecret.ClientID)
	}
	if len(captured.Scope) != 1 || captured.Scope[0] != "files.read" {
		t.Errorf("scope=%v, want [files.read]", captured.Scope)
	}

	// 9. Revocation cascade: revoke the grant and assert the validator
	// flips to 401 on the next request once the introspection cache TTL
	// expires. Use a fresh validator with a 1ms cache so we do not have
	// to wait for the default 60s window.
	if err := a.RevokeDelegation(ctx, grant.ID, "e2e-cascade-check"); err != nil {
		t.Fatalf("RevokeDelegation: %v", err)
	}
	vFresh := mcpresource.New(
		"https://files.example.com/mcp",
		mcpresource.WithJWKS(srv.URL+"/oauth/jwks"),
		mcpresource.WithIntrospection(srv.URL+"/oauth/introspect", agentSecret.ClientID, agentSecret.Secret),
		mcpresource.WithCacheTTL(time.Millisecond),
	)
	revokedHandler := vFresh.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "https://files.example.com/mcp/tool", nil)
	req2.Header.Set("Authorization", "Bearer "+exchanged.AccessToken)
	revokedHandler.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("after revoke want 401, got %d body=%s", rec2.Code, rec2.Body.String())
	}
	if auth := rec2.Header().Get("WWW-Authenticate"); auth == "" {
		t.Fatal("revoked response missing WWW-Authenticate header")
	}
}
