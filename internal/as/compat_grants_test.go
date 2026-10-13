package as_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/internal/models"
	"github.com/glincker/theauth-go/v2/internal/ulid"
)

// compat_grants_test.go: ClientCompat on the grants that do not go through
// /authorize: client_credentials, token exchange and ID-JAG redemption.

func TestClientCredentialsHonorsClientCompat(t *testing.T) {
	tests := []struct {
		name     string
		compat   theauth.ClientCompatConfig
		resource string
		wantErr  error
	}{
		{"strict exact", theauth.ClientCompatConfig{}, compatResource, nil},
		{"strict absent", theauth.ClientCompatConfig{}, "", theauth.ErrOAuthInvalidResource},
		{"strict sub path", theauth.ClientCompatConfig{}, compatResource + "/sse", theauth.ErrOAuthInvalidResource},
		{"optional absent", theauth.ClientCompatConfig{OptionalResource: true}, "", nil},
		{"optional does not allow sub path", theauth.ClientCompatConfig{OptionalResource: true}, compatResource + "/sse", theauth.ErrOAuthInvalidResource},
		{"path audience sub path", theauth.ClientCompatConfig{PathAudience: true}, compatResource + "/sse", nil},
		{"path audience does not allow absent", theauth.ClientCompatConfig{PathAudience: true}, "", theauth.ErrOAuthInvalidResource},
		{"path audience sibling", theauth.ClientCompatConfig{PathAudience: true}, compatResource + "-admin", theauth.ErrOAuthInvalidResource},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a, store := newAgentASInstance(t, func(c *theauth.AuthorizationServerConfig) { c.ClientCompat = tc.compat })
			ctx := context.Background()
			user := theauth.User{ID: ulid.New(), Email: "owner@example.com"}
			if _, err := store.CreateUser(ctx, user); err != nil {
				t.Fatal(err)
			}
			uid := user.ID
			_, secret, err := a.CreateAgent(ctx, theauth.CreateAgentInput{
				Owner: theauth.AgentOwner{UserID: &uid}, Name: "demo", Scope: []string{"files.read"},
			})
			if err != nil {
				t.Fatal(err)
			}
			tok, err := a.ClientCredentialsToken(ctx, theauth.TokenRequest{
				GrantType: theauth.GrantTypeClientCredentials, ClientID: secret.ClientID, ClientSecret: secret.Secret,
				Resource: tc.resource, Scope: []string{"files.read"},
			})
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ClientCredentialsToken: %v", err)
			}
			wantAud := compatResource
			if tc.resource == compatResource {
				wantAud = tc.resource
			}
			if got := decodeJWTPayload(t, tok.AccessToken)["aud"]; got != wantAud {
				t.Errorf("aud = %v, want canonical %q", got, wantAud)
			}
		})
	}
}

func TestTokenExchangeHonorsPathAudience(t *testing.T) {
	for _, tc := range []struct {
		name    string
		compat  theauth.ClientCompatConfig
		wantErr error
	}{
		{"strict rejects sub path", theauth.ClientCompatConfig{}, theauth.ErrOAuthInvalidResource},
		{"optional alone rejects sub path", theauth.ClientCompatConfig{OptionalResource: true}, theauth.ErrOAuthInvalidResource},
		{"path audience accepts sub path", theauth.ClientCompatConfig{PathAudience: true}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, store := newAgentASInstance(t, func(c *theauth.AuthorizationServerConfig) { c.ClientCompat = tc.compat })
			ctx := context.Background()
			user := theauth.User{ID: ulid.New(), Email: "u@example.com"}
			_, _ = store.CreateUser(ctx, user)
			uid := user.ID
			agent, secret, err := a.CreateAgent(ctx, theauth.CreateAgentInput{
				Owner: theauth.AgentOwner{UserID: &uid}, Name: "agent-a", Scope: []string{"files.read"},
			})
			if err != nil {
				t.Fatal(err)
			}
			userAccess := userTokenForDelegation(t, a, user, confidentialClient(t, a))
			if _, err := a.GrantDelegation(ctx, theauth.GrantDelegationInput{
				UserID: user.ID, AgentID: agent.ID, Scope: []string{"files.read"},
				Resource: compatResource, MaxDurationSeconds: 3600,
			}); err != nil {
				t.Fatal(err)
			}
			tok, err := a.ExchangeToken(ctx, theauth.TokenExchangeRequest{
				ClientID: secret.ClientID, ClientSecret: secret.Secret,
				SubjectToken: userAccess, SubjectTokenType: theauth.TokenTypeAccessToken,
				Resource: compatResource + "/sse", Scope: []string{"files.read"},
			})
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ExchangeToken: %v", err)
			}
			if got := decodeJWTPayload(t, tok.AccessToken)["aud"]; got != compatResource {
				t.Errorf("aud = %v, want canonical %q", got, compatResource)
			}
		})
	}
}

func TestIDJAGRedeemHonorsClientCompat(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuers := []theauth.TrustedJWTIssuer{{
		Issuer: jagIDP, JWKSURL: jwksServerForECKey(t, &priv.PublicKey),
		AllowedAlgorithms: []string{"ES256"}, SubjectMapper: theauth.SubMapper{},
	}}
	tests := []struct {
		name      string
		compat    theauth.ClientCompatConfig
		claimRes  string
		presented string
		wantErr   bool
	}{
		{"strict exact", theauth.ClientCompatConfig{}, jagResource, jagResource, false},
		{"strict sub path presented", theauth.ClientCompatConfig{}, jagResource, jagResource + "/sse", true},
		{"path audience sub path presented", theauth.ClientCompatConfig{PathAudience: true}, jagResource, jagResource + "/sse", false},
		{"path audience sub path claimed", theauth.ClientCompatConfig{PathAudience: true}, jagResource + "/sse", jagResource, false},
		{"path audience different resource still rejected", theauth.ClientCompatConfig{PathAudience: true}, "https://other.example.com/mcp", jagResource + "/sse", true},
		{"optional presents none", theauth.ClientCompatConfig{OptionalResource: true}, jagResource, "", false},
		{"strict presents none", theauth.ClientCompatConfig{}, jagResource, "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a, _ := newIDJAGInstance(t, &theauth.IDJAGConfig{}, issuers, func(c *theauth.AuthorizationServerConfig) { c.ClientCompat = tc.compat })
			client := confidentialClient(t, a)
			assertion := jagAssertion(t, priv, "oauth-id-jag+jwt", func(c map[string]any) {
				c["client_id"] = client.ClientID
				c["resource"] = tc.claimRes
			})
			resp, err := a.JWTBearerGrant(context.Background(), theauth.TokenRequest{
				GrantType: models.GrantTypeJWTBearer, ClientID: client.ClientID, ClientSecret: client.ClientSecret,
				Resource: tc.presented, Scope: []string{"api.read"}, Assertion: assertion,
			}, assertion)
			if tc.wantErr {
				if err == nil {
					t.Fatal("redemption accepted")
				}
				return
			}
			if err != nil {
				t.Fatalf("redeem: %v", err)
			}
			if got := decodeJWTPayload(t, resp.AccessToken)["aud"]; got != jagResource {
				t.Errorf("aud = %v, want %q", got, jagResource)
			}
		})
	}
}
