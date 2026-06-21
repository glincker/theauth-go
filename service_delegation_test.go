package theauth_test

import (
	"context"
	"errors"
	"testing"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/crypto"
	"github.com/glincker/theauth-go/internal/ulid"
)

// userTokenForDelegation mints a user access token via the authorization
// code flow against the supplied confidential client. Returned alongside
// the user struct so the caller can drive delegation grant creation against
// that user. The token's aud is bound to the resource the test fixture
// configures.
func userTokenForDelegation(t *testing.T, a *theauth.TheAuth, user theauth.User, client theauth.RegisteredClient) string {
	t.Helper()
	verifier, _ := crypto.NewCodeVerifier()
	authzReq := theauth.AuthorizeRequest{
		ClientID:            client.ClientID,
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
	tok, err := a.ExchangeAuthorizationCode(ctx, theauth.TokenRequest{
		GrantType:    theauth.GrantTypeAuthorizationCode,
		ClientID:     client.ClientID,
		ClientSecret: client.ClientSecret,
		Code:         code,
		CodeVerifier: verifier,
		RedirectURI:  "https://app.example.com/cb",
	})
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode: %v", err)
	}
	return tok.AccessToken
}

func TestGrantDelegationRejectsScopeOutsideResource(t *testing.T) {
	a, store := newAgentASInstance(t)
	ctx := context.Background()
	user := theauth.User{ID: ulid.New(), Email: "u@example.com"}
	_, _ = store.CreateUser(ctx, user)
	uid := user.ID
	agent, _, _ := a.CreateAgent(ctx, theauth.CreateAgentInput{
		Owner: theauth.AgentOwner{UserID: &uid},
		Name:  "agent",
		Scope: []string{"files.read"},
	})
	_, err := a.GrantDelegation(ctx, theauth.GrantDelegationInput{
		UserID:             user.ID,
		AgentID:            agent.ID,
		Scope:              []string{"files.unknown"},
		Resource:           "https://files.example.com/mcp",
		MaxDurationSeconds: 3600,
	})
	if !errors.Is(err, theauth.ErrOAuthInvalidScope) {
		t.Fatalf("expected invalid_scope, got %v", err)
	}
}

func TestTokenExchangeChainAndNarrowing(t *testing.T) {
	a, store := newAgentASInstance(t)
	ctx := context.Background()
	user := theauth.User{ID: ulid.New(), Email: "u@example.com"}
	_, _ = store.CreateUser(ctx, user)
	uid := user.ID
	agentA, secretA, _ := a.CreateAgent(ctx, theauth.CreateAgentInput{
		Owner: theauth.AgentOwner{UserID: &uid},
		Name:  "agent-a",
		Scope: []string{"files.read", "files.write"},
	})
	agentB, secretB, _ := a.CreateAgent(ctx, theauth.CreateAgentInput{
		Owner: theauth.AgentOwner{UserID: &uid},
		Name:  "agent-b",
		Scope: []string{"files.read"},
	})
	agentC, secretC, _ := a.CreateAgent(ctx, theauth.CreateAgentInput{
		Owner: theauth.AgentOwner{UserID: &uid},
		Name:  "agent-c",
		Scope: []string{"files.read"},
	})

	clientForUser := confidentialClient(t, a)
	userAccess := userTokenForDelegation(t, a, user, clientForUser)

	// User delegates files.read + files.write to agent A on resource R.
	grantA, err := a.GrantDelegation(ctx, theauth.GrantDelegationInput{
		UserID:             user.ID,
		AgentID:            agentA.ID,
		Scope:              []string{"files.read", "files.write"},
		Resource:           "https://files.example.com/mcp",
		MaxDurationSeconds: 3600,
	})
	if err != nil {
		t.Fatalf("GrantDelegation A: %v", err)
	}

	// Agent A: token-exchange with scope narrowed to files.read.
	tA, err := a.ExchangeToken(ctx, theauth.TokenExchangeRequest{
		ClientID:         secretA.ClientID,
		ClientSecret:     secretA.Secret,
		SubjectToken:     userAccess,
		SubjectTokenType: theauth.TokenTypeAccessToken,
		Resource:         "https://files.example.com/mcp",
		Scope:            []string{"files.read"},
	})
	if err != nil {
		t.Fatalf("ExchangeToken A: %v", err)
	}
	if tA.IssuedTokenType != theauth.TokenTypeAccessToken {
		t.Fatalf("issued_token_type missing on exchange response: %+v", tA)
	}
	if tA.Scope != "files.read" {
		t.Fatalf("scope narrowing failed: want files.read, got %q", tA.Scope)
	}

	// Introspect T_A: act.sub must name agent A and aud equals resource.
	respA, _, err := a.IntrospectToken(ctx, tA.AccessToken, secretA.ClientID, secretA.Secret, "https://files.example.com/mcp")
	if err != nil {
		t.Fatal(err)
	}
	if !respA.Active || respA.Sub != user.ID.String() {
		t.Fatalf("introspect T_A: %+v", respA)
	}
	if respA.Act == nil || respA.Act.Sub != theauth.AgentSubjectPrefix+agentA.ID.String() {
		t.Fatalf("expected act.sub = agent:A, got %+v", respA.Act)
	}
	if respA.DelegationGrantID != grantA.ID.String() {
		t.Fatalf("delegation_grant_id mismatch: want %s, got %s", grantA.ID, respA.DelegationGrantID)
	}

	// Now agent B holds T_A and sub-delegates to itself. First the user
	// must delegate to agent B as well.
	grantB, err := a.GrantDelegation(ctx, theauth.GrantDelegationInput{
		UserID:             user.ID,
		AgentID:            agentB.ID,
		Scope:              []string{"files.read"},
		Resource:           "https://files.example.com/mcp",
		MaxDurationSeconds: 1800,
	})
	if err != nil {
		t.Fatalf("GrantDelegation B: %v", err)
	}
	_ = grantB

	tB, err := a.ExchangeToken(ctx, theauth.TokenExchangeRequest{
		ClientID:         secretB.ClientID,
		ClientSecret:     secretB.Secret,
		SubjectToken:     tA.AccessToken,
		SubjectTokenType: theauth.TokenTypeAccessToken,
		Resource:         "https://files.example.com/mcp",
		Scope:            []string{"files.read"},
	})
	if err != nil {
		t.Fatalf("ExchangeToken B: %v", err)
	}
	respB, _, err := a.IntrospectToken(ctx, tB.AccessToken, secretB.ClientID, secretB.Secret, "https://files.example.com/mcp")
	if err != nil {
		t.Fatal(err)
	}
	if respB.Act == nil || respB.Act.Sub != theauth.AgentSubjectPrefix+agentB.ID.String() {
		t.Fatalf("expected act.sub = agent:B, got %+v", respB.Act)
	}
	if respB.Act.Act == nil || respB.Act.Act.Sub != theauth.AgentSubjectPrefix+agentA.ID.String() {
		t.Fatalf("expected act.act.sub = agent:A, got %+v", respB.Act.Act)
	}

	// Now agent C tries to sub-delegate further (chain depth would become 4
	// which exceeds MaxChainDepth=3). Even with a grant in place the AS
	// must refuse with ErrChainDepthExceeded.
	if _, err := a.GrantDelegation(ctx, theauth.GrantDelegationInput{
		UserID:             user.ID,
		AgentID:            agentC.ID,
		Scope:              []string{"files.read"},
		Resource:           "https://files.example.com/mcp",
		MaxDurationSeconds: 600,
	}); err != nil {
		t.Fatalf("GrantDelegation C: %v", err)
	}
	if _, err := a.ExchangeToken(ctx, theauth.TokenExchangeRequest{
		ClientID:         secretC.ClientID,
		ClientSecret:     secretC.Secret,
		SubjectToken:     tB.AccessToken,
		SubjectTokenType: theauth.TokenTypeAccessToken,
		Resource:         "https://files.example.com/mcp",
		Scope:            []string{"files.read"},
	}); !errors.Is(err, theauth.ErrChainDepthExceeded) {
		t.Fatalf("expected ErrChainDepthExceeded for fourth link, got %v", err)
	}

	// Scope narrowing: ask for a scope outside the delegation grant.
	if _, err := a.ExchangeToken(ctx, theauth.TokenExchangeRequest{
		ClientID:         secretB.ClientID,
		ClientSecret:     secretB.Secret,
		SubjectToken:     tA.AccessToken,
		SubjectTokenType: theauth.TokenTypeAccessToken,
		Resource:         "https://files.example.com/mcp",
		Scope:            []string{"files.write"},
	}); !errors.Is(err, theauth.ErrOAuthInvalidScope) {
		t.Fatalf("expected invalid_scope on out-of-grant request, got %v", err)
	}

	// Revoke grant A. Introspection on T_A must now flip active=false and
	// the cached body must be ignored.
	if err := a.RevokeDelegation(ctx, grantA.ID, "test"); err != nil {
		t.Fatalf("RevokeDelegation: %v", err)
	}
	rev, _, err := a.IntrospectToken(ctx, tA.AccessToken, secretA.ClientID, secretA.Secret, "https://files.example.com/mcp")
	if err != nil {
		t.Fatal(err)
	}
	if rev.Active {
		t.Fatalf("expected active=false after grant revoke, got %+v", rev)
	}
}

func TestTokenExchangeRejectsAgentRootedSubject(t *testing.T) {
	a, store := newAgentASInstance(t)
	ctx := context.Background()
	user := theauth.User{ID: ulid.New(), Email: "u@example.com"}
	_, _ = store.CreateUser(ctx, user)
	uid := user.ID
	_, secretA, _ := a.CreateAgent(ctx, theauth.CreateAgentInput{
		Owner: theauth.AgentOwner{UserID: &uid},
		Name:  "self",
		Scope: []string{"files.read"},
	})
	// Mint an agent-rooted token via client_credentials. The spec forbids
	// using it as subject_token for an exchange because there is no user
	// authority behind it.
	selfTok, err := a.ClientCredentialsToken(ctx, theauth.TokenRequest{
		GrantType:    theauth.GrantTypeClientCredentials,
		ClientID:     secretA.ClientID,
		ClientSecret: secretA.Secret,
		Resource:     "https://files.example.com/mcp",
		Scope:        []string{"files.read"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.ExchangeToken(ctx, theauth.TokenExchangeRequest{
		ClientID:         secretA.ClientID,
		ClientSecret:     secretA.Secret,
		SubjectToken:     selfTok.AccessToken,
		SubjectTokenType: theauth.TokenTypeAccessToken,
		Resource:         "https://files.example.com/mcp",
		Scope:            []string{"files.read"},
	}); !errors.Is(err, theauth.ErrSubjectTokenInvalid) {
		t.Fatalf("expected ErrSubjectTokenInvalid on agent-rooted subject, got %v", err)
	}
}
