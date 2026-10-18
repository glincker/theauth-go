package as_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/internal/ulid"
	"github.com/glincker/theauth-go/v2/storage/memory"
)

const expiryResource = "https://files.example.com/mcp"

// newExpiryInstance builds an agent AS on a fake clock that starts at the real time, so the agent
// service (which validates expiries against the wall clock) and the AS agree.
func newExpiryInstance(t *testing.T) (*theauth.TheAuth, *memory.Store, *fakeClock) {
	t.Helper()
	clock := newFakeClock(time.Now().UTC().Truncate(time.Second))
	a, store := newAgentASInstance(t, func(c *theauth.AuthorizationServerConfig) {
		c.Clock = clock
	})
	return a, store, clock
}

func newExpiryUser(t *testing.T, store *memory.Store) theauth.User {
	t.Helper()
	user := theauth.User{ID: ulid.New(), Email: "owner-" + ulid.New().String() + "@example.com"}
	if _, err := store.CreateUser(context.Background(), user); err != nil {
		t.Fatal(err)
	}
	return user
}

func ccRequest(secret theauth.AgentSecret) theauth.TokenRequest {
	return theauth.TokenRequest{
		GrantType:    theauth.GrantTypeClientCredentials,
		ClientID:     secret.ClientID,
		ClientSecret: secret.Secret,
		Resource:     expiryResource,
		Scope:        []string{"files.read"},
	}
}

func TestCreateAgentExpiryValidation(t *testing.T) {
	a, store, _ := newExpiryInstance(t)
	ctx := context.Background()
	uid := newExpiryUser(t, store).ID
	past := time.Now().Add(-time.Minute)
	far := time.Now().Add(11 * 365 * 24 * time.Hour)
	ok := time.Now().Add(time.Hour)
	tests := []struct {
		name    string
		exp     *time.Time
		wantErr error
	}{
		{"nil means no expiry", nil, nil},
		{"future within bound", &ok, nil},
		{"past rejected", &past, theauth.ErrAgentExpiryInvalid},
		{"absurdly far rejected", &far, theauth.ErrAgentExpiryInvalid},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ag, _, err := a.CreateAgent(ctx, theauth.CreateAgentInput{
				Owner: theauth.AgentOwner{UserID: &uid}, Name: "x", Scope: []string{"files.read"}, ExpiresAt: tc.exp,
			})
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if err == nil && (tc.exp == nil) != (ag.ExpiresAt == nil) {
				t.Fatalf("ExpiresAt = %v, want %v", ag.ExpiresAt, tc.exp)
			}
		})
	}
}

func TestClientCredentialsCappedAndDeniedAfterExpiry(t *testing.T) {
	a, store, clock := newExpiryInstance(t)
	ctx := context.Background()
	uid := newExpiryUser(t, store).ID
	exp := clock.Now().Add(2 * time.Minute)
	agent, secret, err := a.CreateAgent(ctx, theauth.CreateAgentInput{
		Owner: theauth.AgentOwner{UserID: &uid}, Name: "short-lived", Scope: []string{"files.read"}, ExpiresAt: &exp,
	})
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	tok, err := a.ClientCredentialsToken(ctx, ccRequest(secret))
	if err != nil {
		t.Fatalf("ClientCredentialsToken: %v", err)
	}
	if tok.ExpiresIn > 120 {
		t.Fatalf("ExpiresIn = %d, want at most 120 (agent expiry)", tok.ExpiresIn)
	}
	resp, _, err := a.IntrospectToken(ctx, tok.AccessToken, secret.ClientID, secret.Secret, expiryResource)
	if err != nil || !resp.Active {
		t.Fatalf("introspect before expiry = %+v, %v", resp, err)
	}
	if resp.Exp > exp.Unix() {
		t.Fatalf("token exp %d outlives agent expiry %d", resp.Exp, exp.Unix())
	}

	clock.Advance(3 * time.Minute)
	_, err = a.ClientCredentialsToken(ctx, ccRequest(secret))
	if !errors.Is(err, theauth.ErrAgentExpired) || !errors.Is(err, theauth.ErrAgentInactive) {
		t.Fatalf("mint after expiry err = %v, want ErrAgentExpired matching ErrAgentInactive", err)
	}
	_ = agent
}

func TestIntrospectionInactiveWhenAgentExpiryReached(t *testing.T) {
	a, store, clock := newExpiryInstance(t)
	ctx := context.Background()
	uid := newExpiryUser(t, store).ID
	agent, secret, err := a.CreateAgent(ctx, theauth.CreateAgentInput{
		Owner: theauth.AgentOwner{UserID: &uid}, Name: "no-expiry-yet", Scope: []string{"files.read"},
	})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := a.ClientCredentialsToken(ctx, ccRequest(secret))
	if err != nil {
		t.Fatal(err)
	}
	resp, _, err := a.IntrospectToken(ctx, tok.AccessToken, secret.ClientID, secret.Secret, expiryResource)
	if err != nil || !resp.Active {
		t.Fatalf("introspect = %+v, %v", resp, err)
	}
	// The token itself is good for much longer than the agent. Shortening the agent expiry must
	// flip it to inactive once the agent expiry passes.
	exp := clock.Now().Add(time.Minute)
	if err := a.SetAgentExpiry(ctx, agent.ID, &exp); err != nil {
		t.Fatalf("SetAgentExpiry: %v", err)
	}
	resp, _, _ = a.IntrospectToken(ctx, tok.AccessToken, secret.ClientID, secret.Secret, expiryResource)
	if !resp.Active {
		t.Fatalf("still before expiry, want active: %+v", resp)
	}
	clock.Advance(2 * time.Minute)
	resp, _, _ = a.IntrospectToken(ctx, tok.AccessToken, secret.ClientID, secret.Secret, expiryResource)
	if resp.Active {
		t.Fatalf("agent expired, token must be inactive: %+v", resp)
	}
	// Clearing the expiry lets the agent mint again.
	if err := a.SetAgentExpiry(ctx, agent.ID, nil); err != nil {
		t.Fatalf("SetAgentExpiry clear: %v", err)
	}
	if _, err := a.ClientCredentialsToken(ctx, ccRequest(secret)); err != nil {
		t.Fatalf("mint after clearing expiry: %v", err)
	}
}

func TestSetAgentExpiryValidation(t *testing.T) {
	a, store, _ := newExpiryInstance(t)
	ctx := context.Background()
	uid := newExpiryUser(t, store).ID
	agent, _, err := a.CreateAgent(ctx, theauth.CreateAgentInput{Owner: theauth.AgentOwner{UserID: &uid}, Name: "x", Scope: []string{"files.read"}})
	if err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-time.Hour)
	if err := a.SetAgentExpiry(ctx, agent.ID, &past); !errors.Is(err, theauth.ErrAgentExpiryInvalid) {
		t.Fatalf("past expiry err = %v", err)
	}
	future := time.Now().Add(time.Hour)
	if err := a.SetAgentExpiry(ctx, ulid.New(), &future); !errors.Is(err, theauth.ErrAgentNotFound) {
		t.Fatalf("unknown agent err = %v", err)
	}
}

func TestExchangeExpiredAgentAndChainDenied(t *testing.T) {
	a, store, clock := newExpiryInstance(t)
	ctx := context.Background()
	user := newExpiryUser(t, store)
	uid := user.ID
	shortExp := clock.Now().Add(10 * time.Minute)
	agentA, secretA, err := a.CreateAgent(ctx, theauth.CreateAgentInput{
		Owner: theauth.AgentOwner{UserID: &uid}, Name: "a", Scope: []string{"files.read"}, ExpiresAt: &shortExp,
	})
	if err != nil {
		t.Fatal(err)
	}
	agentB, secretB, err := a.CreateAgent(ctx, theauth.CreateAgentInput{
		Owner: theauth.AgentOwner{UserID: &uid}, Name: "b", Scope: []string{"files.read"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []theauth.ULID{agentA.ID, agentB.ID} {
		if _, err := a.GrantDelegation(ctx, theauth.GrantDelegationInput{
			UserID: user.ID, AgentID: id, Scope: []string{"files.read"}, Resource: expiryResource, MaxDurationSeconds: 7200,
		}); err != nil {
			t.Fatalf("GrantDelegation: %v", err)
		}
	}
	userAccess := userTokenForDelegation(t, a, user, confidentialClient(t, a))
	exch := func(secret theauth.AgentSecret, subject string) (theauth.TokenResponse, error) {
		return a.ExchangeToken(ctx, theauth.TokenExchangeRequest{
			ClientID: secret.ClientID, ClientSecret: secret.Secret, SubjectToken: subject,
			SubjectTokenType: theauth.TokenTypeAccessToken, Resource: expiryResource, Scope: []string{"files.read"},
		})
	}

	tA, err := exch(secretA, userAccess)
	if err != nil {
		t.Fatalf("exchange A: %v", err)
	}
	respA, _, err := a.IntrospectToken(ctx, tA.AccessToken, secretA.ClientID, secretA.Secret, expiryResource)
	if err != nil || !respA.Active {
		t.Fatalf("introspect A = %+v, %v", respA, err)
	}
	if respA.Exp > shortExp.Unix() {
		t.Fatalf("exchanged token exp %d outlives agent expiry %d", respA.Exp, shortExp.Unix())
	}
	// B extends the chain through A: the new token is capped by A's expiry too.
	tB, err := exch(secretB, tA.AccessToken)
	if err != nil {
		t.Fatalf("exchange B: %v", err)
	}
	respB, _, err := a.IntrospectToken(ctx, tB.AccessToken, secretB.ClientID, secretB.Secret, expiryResource)
	if err != nil || !respB.Active {
		t.Fatalf("introspect B = %+v, %v", respB, err)
	}
	if respB.Exp > shortExp.Unix() {
		t.Fatalf("chained token exp %d outlives expired-link expiry %d", respB.Exp, shortExp.Unix())
	}

	// Shorten A to the near future (still unexpired), then pass it. A user token that is still
	// valid cannot be exchanged by an expired agent, and a chain through A cannot lend permissions.
	soon := clock.Now().Add(time.Minute)
	if err := a.SetAgentExpiry(ctx, agentA.ID, &soon); err != nil {
		t.Fatal(err)
	}
	clock.Advance(2 * time.Minute)
	if _, err := exch(secretA, userAccess); !errors.Is(err, theauth.ErrAgentExpired) {
		t.Fatalf("expired agent exchange err = %v, want ErrAgentExpired", err)
	}
	if _, err := exch(secretB, tA.AccessToken); !errors.Is(err, theauth.ErrAgentExpired) {
		t.Fatalf("exchange through expired link err = %v, want ErrAgentExpired", err)
	}
	if resp, _, _ := a.IntrospectToken(ctx, tB.AccessToken, secretB.ClientID, secretB.Secret, expiryResource); resp.Active {
		t.Fatalf("token through expired agent must be inactive: %+v", resp)
	}
	// Agent B itself is not expired, so it can still use a fresh user token.
	if _, err := exch(secretB, userAccess); err != nil {
		t.Fatalf("unexpired agent exchange: %v", err)
	}
}

func TestGrantDelegationRefusesExpiredAgent(t *testing.T) {
	a, store, _ := newExpiryInstance(t)
	ctx := context.Background()
	user := newExpiryUser(t, store)
	uid := user.ID
	agent, _, err := a.CreateAgent(ctx, theauth.CreateAgentInput{Owner: theauth.AgentOwner{UserID: &uid}, Name: "x", Scope: []string{"files.read"}})
	if err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-time.Minute)
	if err := store.UpdateAgentExpiry(ctx, agent.ID, &past); err != nil {
		t.Fatal(err)
	}
	_, err = a.GrantDelegation(ctx, theauth.GrantDelegationInput{
		UserID: user.ID, AgentID: agent.ID, Scope: []string{"files.read"}, Resource: expiryResource, MaxDurationSeconds: 60,
	})
	if !errors.Is(err, theauth.ErrAgentExpired) {
		t.Fatalf("err = %v, want ErrAgentExpired", err)
	}
}
