package as_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/crypto"
	internalas "github.com/glincker/theauth-go/v2/internal/as"
	"github.com/glincker/theauth-go/v2/internal/ulid"
)

const (
	hardeningResource = "https://files.example.com/mcp"
	hardeningTokenURL = "https://auth.example.com/oauth/token"
)

func hardeningInstance(t *testing.T, dpop, revocation bool) (*theauth.TheAuth, theauth.User) {
	t.Helper()
	a, store := newAgentASInstance(t, func(c *theauth.AuthorizationServerConfig) {
		if dpop {
			c.DPoP = &theauth.DPoPConfig{}
		}
		c.AccessTokenRevocation = revocation
	})
	user := theauth.User{ID: ulid.New(), Email: "h@example.com"}
	if _, err := store.CreateUser(context.Background(), user); err != nil {
		t.Fatal(err)
	}
	return a, user
}

func hardeningCode(t *testing.T, a *theauth.TheAuth, user theauth.User, client theauth.RegisteredClient) (code, verifier string) {
	t.Helper()
	verifier, _ = crypto.NewCodeVerifier()
	res, err := a.StartAuthorize(context.Background(), theauth.AuthorizeRequest{
		ClientID:            client.ClientID,
		RedirectURI:         "https://app.example.com/cb",
		ResponseType:        "code",
		Scope:               []string{"files.read"},
		CodeChallenge:       crypto.CodeChallenge(verifier),
		CodeChallengeMethod: "S256",
		Resource:            hardeningResource,
	}, &user)
	if err != nil {
		t.Fatalf("StartAuthorize: %v", err)
	}
	return codeFromRedirect(t, res.RedirectURL), verifier
}

func hardeningExchange(t *testing.T, a *theauth.TheAuth, client theauth.RegisteredClient, code, verifier, proof string) (theauth.TokenResponse, error) {
	t.Helper()
	return a.ExchangeAuthorizationCode(context.Background(), theauth.TokenRequest{
		GrantType: theauth.GrantTypeAuthorizationCode, ClientID: client.ClientID, ClientSecret: client.ClientSecret,
		Code: code, CodeVerifier: verifier, RedirectURI: "https://app.example.com/cb",
		DPoPProof: proof, HTTPMethod: "POST", HTTPURL: hardeningTokenURL,
	})
}

func hardeningRefresh(a *theauth.TheAuth, client theauth.RegisteredClient, rt, proof string) (theauth.TokenResponse, error) {
	return a.RefreshAccessToken(context.Background(), theauth.TokenRequest{
		GrantType: theauth.GrantTypeRefreshToken, ClientID: client.ClientID, ClientSecret: client.ClientSecret,
		RefreshToken: rt, DPoPProof: proof, HTTPMethod: "POST", HTTPURL: hardeningTokenURL,
	})
}

func newP256(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// Authorization codes are stored as SHA-256 hashes, never plaintext.
func TestAuthorizationCodeStoredHashed(t *testing.T) {
	a, store := newASInstance(t)
	user := theauth.User{ID: ulid.New(), Email: "h@example.com"}
	_, _ = store.CreateUser(context.Background(), user)
	client := confidentialClient(t, a)
	code, _ := hardeningCode(t, a, user, client)

	if _, err := store.ConsumeAuthorizationCode(context.Background(), code); err == nil {
		t.Fatal("plaintext code must not be a storage key")
	}
	sum := crypto.HashToken(code)
	row, err := store.ConsumeAuthorizationCode(context.Background(), hex.EncodeToString(sum))
	if err != nil {
		t.Fatalf("hashed key should resolve: %v", err)
	}
	if row.Code == code {
		t.Fatal("stored code equals plaintext")
	}
}

// Replaying a redeemed code revokes the tokens already issued from it.
func TestAuthorizationCodeReplayRevokesIssuedTokens(t *testing.T) {
	tests := []struct {
		name       string
		revocation bool
	}{
		{"refresh token revoked", false},
		{"refresh and access token revoked with denylist", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a, user := hardeningInstance(t, false, tc.revocation)
			client := confidentialClient(t, a)
			code, verifier := hardeningCode(t, a, user, client)
			tok, err := hardeningExchange(t, a, client, code, verifier, "")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := hardeningExchange(t, a, client, code, verifier, ""); !errors.Is(err, theauth.ErrOAuthInvalidGrant) {
				t.Fatalf("replay: want invalid_grant, got %v", err)
			}
			if _, err := hardeningRefresh(a, client, tok.RefreshToken, ""); !errors.Is(err, theauth.ErrOAuthInvalidGrant) {
				t.Fatalf("refresh after replay: want invalid_grant, got %v", err)
			}
			resp, _, err := a.IntrospectToken(context.Background(), tok.AccessToken, client.ClientID, client.ClientSecret, hardeningResource)
			if err != nil {
				t.Fatal(err)
			}
			if resp.Active == tc.revocation {
				t.Fatalf("access token active=%v, want %v", resp.Active, !tc.revocation)
			}
		})
	}
}

// RFC 9449 section 8: DPoP-bound refresh tokens need a matching proof.
func TestRefreshTokenDPoPBinding(t *testing.T) {
	tests := []struct {
		name    string
		proof   func(t *testing.T, bound *ecdsa.PrivateKey) string
		wantErr bool
	}{
		{"no proof rejected", func(*testing.T, *ecdsa.PrivateKey) string { return "" }, true},
		{"other key rejected", func(t *testing.T, _ *ecdsa.PrivateKey) string {
			return makeDPoPProof(t, newP256(t), "POST", hardeningTokenURL, "", time.Now())
		}, true},
		{"bound key accepted", func(t *testing.T, k *ecdsa.PrivateKey) string {
			return makeDPoPProof(t, k, "POST", hardeningTokenURL, "", time.Now())
		}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a, user := hardeningInstance(t, true, false)
			client := confidentialClient(t, a)
			key := newP256(t)
			code, verifier := hardeningCode(t, a, user, client)
			tok, err := hardeningExchange(t, a, client, code, verifier, makeDPoPProof(t, key, "POST", hardeningTokenURL, "", time.Now()))
			if err != nil {
				t.Fatal(err)
			}
			if tok.TokenType != "DPoP" {
				t.Fatalf("token_type=%q", tok.TokenType)
			}
			next, err := hardeningRefresh(a, client, tok.RefreshToken, tc.proof(t, key))
			if tc.wantErr {
				if !errors.Is(err, internalas.ErrDPoPInvalid) {
					t.Fatalf("want ErrDPoPInvalid, got %v", err)
				}
				// A failed proof must not burn the refresh token.
				good := makeDPoPProof(t, key, "POST", hardeningTokenURL, "", time.Now())
				if _, err := hardeningRefresh(a, client, tok.RefreshToken, good); err != nil {
					t.Fatalf("token should survive failed proof: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if next.TokenType != "DPoP" {
				t.Fatalf("refreshed token downgraded to %q", next.TokenType)
			}
		})
	}
}

// Token exchange cannot launder a DPoP-bound subject token into a bearer.
func TestTokenExchangeDPoPPropagation(t *testing.T) {
	tests := []struct {
		name    string
		proofBy func(t *testing.T, bound *ecdsa.PrivateKey) string
		wantErr bool
	}{
		{"no proof rejected", func(*testing.T, *ecdsa.PrivateKey) string { return "" }, true},
		{"other key rejected", func(t *testing.T, _ *ecdsa.PrivateKey) string {
			return makeDPoPProof(t, newP256(t), "POST", hardeningTokenURL, "", time.Now())
		}, true},
		{"bound key accepted and binding propagated", func(t *testing.T, k *ecdsa.PrivateKey) string {
			return makeDPoPProof(t, k, "POST", hardeningTokenURL, "", time.Now())
		}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a, user := hardeningInstance(t, true, false)
			ctx := context.Background()
			uid := user.ID
			agent, secret, err := a.CreateAgent(ctx, theauth.CreateAgentInput{
				Owner: theauth.AgentOwner{UserID: &uid}, Name: "ag", Scope: []string{"files.read"},
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := a.GrantDelegation(ctx, theauth.GrantDelegationInput{
				UserID: user.ID, AgentID: agent.ID, Scope: []string{"files.read"},
				Resource: hardeningResource, MaxDurationSeconds: 3600,
			}); err != nil {
				t.Fatal(err)
			}
			client := confidentialClient(t, a)
			key := newP256(t)
			code, verifier := hardeningCode(t, a, user, client)
			subj, err := hardeningExchange(t, a, client, code, verifier, makeDPoPProof(t, key, "POST", hardeningTokenURL, "", time.Now()))
			if err != nil {
				t.Fatal(err)
			}
			out, err := a.ExchangeToken(ctx, theauth.TokenExchangeRequest{
				ClientID: secret.ClientID, ClientSecret: secret.Secret,
				SubjectToken: subj.AccessToken, SubjectTokenType: theauth.TokenTypeAccessToken,
				Resource: hardeningResource, Scope: []string{"files.read"},
				DPoPProof: tc.proofBy(t, key), HTTPMethod: "POST", HTTPURL: hardeningTokenURL,
			})
			if tc.wantErr {
				if !errors.Is(err, internalas.ErrDPoPInvalid) {
					t.Fatalf("want ErrDPoPInvalid, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if out.TokenType != "DPoP" {
				t.Fatalf("exchanged token_type=%q, want DPoP", out.TokenType)
			}
			resp, _, _ := a.IntrospectToken(ctx, out.AccessToken, secret.ClientID, secret.Secret, hardeningResource)
			if resp.Cnf == nil || resp.Cnf.JKT == "" {
				t.Fatalf("cnf not propagated: %+v", resp)
			}
		})
	}
}

// A revoked (denylisted) subject token cannot be exchanged.
func TestTokenExchangeRejectsRevokedSubject(t *testing.T) {
	a, user := hardeningInstance(t, false, true)
	ctx := context.Background()
	uid := user.ID
	agent, secret, _ := a.CreateAgent(ctx, theauth.CreateAgentInput{
		Owner: theauth.AgentOwner{UserID: &uid}, Name: "ag", Scope: []string{"files.read"},
	})
	_, _ = a.GrantDelegation(ctx, theauth.GrantDelegationInput{
		UserID: user.ID, AgentID: agent.ID, Scope: []string{"files.read"},
		Resource: hardeningResource, MaxDurationSeconds: 3600,
	})
	client := confidentialClient(t, a)
	code, verifier := hardeningCode(t, a, user, client)
	subj, err := hardeningExchange(t, a, client, code, verifier, "")
	if err != nil {
		t.Fatal(err)
	}
	req := theauth.TokenExchangeRequest{
		ClientID: secret.ClientID, ClientSecret: secret.Secret,
		SubjectToken: subj.AccessToken, SubjectTokenType: theauth.TokenTypeAccessToken,
		Resource: hardeningResource, Scope: []string{"files.read"},
	}
	if _, err := a.ExchangeToken(ctx, req); err != nil {
		t.Fatalf("pre-revoke exchange: %v", err)
	}
	if err := a.RevokeToken(ctx, subj.AccessToken, "access_token", client.ClientID, client.ClientSecret); err != nil {
		t.Fatal(err)
	}
	if _, err := a.ExchangeToken(ctx, req); !errors.Is(err, theauth.ErrSubjectTokenInvalid) {
		t.Fatalf("want subject_token_invalid after revoke, got %v", err)
	}
}

// RFC 7009: only the owning client can revoke; access-token revocation is
// real only when the denylist is enabled.
func TestRevokeOwnershipAndAccessTokens(t *testing.T) {
	tests := []struct {
		name       string
		revocation bool
		byOwner    bool
		useAccess  bool
		wantActive bool
	}{
		{"owner revokes refresh", false, true, false, false},
		{"other client cannot revoke refresh", false, false, false, true},
		{"owner revokes access with denylist", true, true, true, false},
		{"other client cannot revoke access", true, false, true, true},
		{"access revoke is no-op without denylist", false, true, true, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a, user := hardeningInstance(t, false, tc.revocation)
			ctx := context.Background()
			owner := confidentialClient(t, a)
			other := confidentialClient(t, a)
			code, verifier := hardeningCode(t, a, user, owner)
			tok, err := hardeningExchange(t, a, owner, code, verifier, "")
			if err != nil {
				t.Fatal(err)
			}
			caller, hint, target := other, "refresh_token", tok.RefreshToken
			if tc.byOwner {
				caller = owner
			}
			if tc.useAccess {
				hint, target = "access_token", tok.AccessToken
			}
			if err := a.RevokeToken(ctx, target, hint, caller.ClientID, caller.ClientSecret); err != nil {
				t.Fatalf("revoke must answer 200 semantics, got %v", err)
			}
			var active bool
			if tc.useAccess {
				r, _, _ := a.IntrospectToken(ctx, tok.AccessToken, owner.ClientID, owner.ClientSecret, hardeningResource)
				active = r.Active
			} else {
				_, rerr := hardeningRefresh(a, owner, tok.RefreshToken, "")
				active = rerr == nil
			}
			if active != tc.wantActive {
				t.Fatalf("active=%v want %v", active, tc.wantActive)
			}
		})
	}
}

func TestMetadataAdvertisesIssAndLegacyDCR(t *testing.T) {
	tests := []struct {
		name         string
		mut          func(*theauth.AuthorizationServerConfig)
		wantRegistry bool
	}{
		{"dcr hidden by default", func(*theauth.AuthorizationServerConfig) {}, false},
		{"dcr advertised with registration token", func(c *theauth.AuthorizationServerConfig) { c.RegistrationTokens = []string{"t"} }, true},
		{"dcr advertised when anonymous allowed", func(c *theauth.AuthorizationServerConfig) { c.AllowAnonymousRegistration = true }, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a, _ := newASInstance(t, tc.mut)
			md, err := a.ASMetadataDoc()
			if err != nil {
				t.Fatal(err)
			}
			if !md.AuthorizationResponseIssParameterSupported {
				t.Fatal("iss parameter support not advertised")
			}
			if (md.RegistrationEndpoint != "") != tc.wantRegistry {
				t.Fatalf("registration_endpoint=%q wantRegistry=%v", md.RegistrationEndpoint, tc.wantRegistry)
			}
		})
	}
}

func TestAuthorizeResponseCarriesIssuer(t *testing.T) {
	a, user := hardeningInstance(t, false, false)
	client := confidentialClient(t, a)
	verifier, _ := crypto.NewCodeVerifier()
	res, err := a.StartAuthorize(context.Background(), theauth.AuthorizeRequest{
		ClientID: client.ClientID, RedirectURI: "https://app.example.com/cb", ResponseType: "code",
		Scope: []string{"files.read"}, CodeChallenge: crypto.CodeChallenge(verifier),
		CodeChallengeMethod: "S256", Resource: hardeningResource,
	}, &user)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.RedirectURL, "iss=https%3A%2F%2Fauth.example.com") {
		t.Fatalf("redirect lacks iss: %s", res.RedirectURL)
	}
}
