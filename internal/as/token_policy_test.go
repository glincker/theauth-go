package as_test

// token_policy_test.go: per-client signing algorithm and opaque access tokens.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/crypto"
	"github.com/glincker/theauth-go/v2/internal/ulid"
	"github.com/glincker/theauth-go/v2/storage/memory"
)

const policyResource = "https://files.example.com/mcp"

func withTokenPolicy(p *theauth.TokenPolicyConfig) func(*theauth.AuthorizationServerConfig) {
	return func(c *theauth.AuthorizationServerConfig) { c.TokenPolicy = p }
}

// registerPolicyClient registers a confidential client with token policy
// metadata through the same path /oauth/register uses.
func registerPolicyClient(t *testing.T, a *theauth.TheAuth, mut func(*theauth.ClientRegistrationRequest)) theauth.RegisteredClient {
	t.Helper()
	req := theauth.ClientRegistrationRequest{
		RedirectURIs:            []string{"https://app.example.com/cb"},
		TokenEndpointAuthMethod: theauth.ClientAuthSecretBasic,
	}
	mut(&req)
	reg, err := a.RegisterClient(context.Background(), req, false)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	return reg
}

// codeFlow runs authorize + code exchange for client and returns the token
// response. tweak may adjust the authorize request.
func codeFlow(t *testing.T, a *theauth.TheAuth, store *memory.Store, client theauth.RegisteredClient, tweak func(*theauth.AuthorizeRequest)) (theauth.TokenResponse, theauth.User) {
	t.Helper()
	ctx := context.Background()
	user := theauth.User{ID: ulid.New(), Email: "u" + ulid.New().String() + "@example.com"}
	if _, err := store.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	verifier, _ := crypto.NewCodeVerifier()
	req := theauth.AuthorizeRequest{
		ClientID:            client.ClientID,
		RedirectURI:         "https://app.example.com/cb",
		ResponseType:        "code",
		Scope:               []string{"files.read"},
		State:               "s",
		CodeChallenge:       crypto.CodeChallenge(verifier),
		CodeChallengeMethod: "S256",
		Resource:            policyResource,
	}
	if tweak != nil {
		tweak(&req)
	}
	res, err := a.StartAuthorize(ctx, req, &user)
	if err != nil {
		t.Fatalf("StartAuthorize: %v", err)
	}
	tok, err := a.ExchangeAuthorizationCode(ctx, theauth.TokenRequest{
		GrantType:    theauth.GrantTypeAuthorizationCode,
		ClientID:     client.ClientID,
		ClientSecret: client.ClientSecret,
		Code:         codeFromRedirect(t, res.RedirectURL),
		CodeVerifier: verifier,
		RedirectURI:  "https://app.example.com/cb",
	})
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode: %v", err)
	}
	return tok, user
}

func jwtHeaderAlg(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", token)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	var h struct{ Alg, Typ string }
	if err := json.Unmarshal(raw, &h); err != nil {
		t.Fatal(err)
	}
	if h.Typ != "at+jwt" {
		t.Fatalf("typ %q, want at+jwt", h.Typ)
	}
	return h.Alg
}

func TestTokenPolicySigningAlgPerClient(t *testing.T) {
	a, store := newASInstance(t, withTokenPolicy(&theauth.TokenPolicyConfig{SigningAlgs: []string{"ES256", "RS256"}}))
	ctx := context.Background()

	for _, alg := range []string{"", "ES256", "RS256"} {
		want := alg
		if want == "" {
			want = "EdDSA"
		}
		t.Run(want, func(t *testing.T) {
			client := registerPolicyClient(t, a, func(r *theauth.ClientRegistrationRequest) { r.AccessTokenSignedResponseAlg = alg })
			tok, _ := codeFlow(t, a, store, client, nil)
			if got := jwtHeaderAlg(t, tok.AccessToken); got != want {
				t.Fatalf("alg %q, want %q", got, want)
			}
			resp, _, err := a.IntrospectToken(ctx, tok.AccessToken, client.ClientID, client.ClientSecret, policyResource)
			if err != nil || !resp.Active {
				t.Fatalf("introspect: active=%v err=%v", resp.Active, err)
			}
		})
	}

	keys, err := store.JWKSKeysAll(ctx)
	if err != nil {
		t.Fatal(err)
	}
	algs := map[string]int{}
	for _, k := range keys {
		algs[k.Alg]++
	}
	for _, alg := range []string{"EdDSA", "ES256", "RS256"} {
		if algs[alg] != 2 {
			t.Fatalf("want a current and a next key for %s, got %v", alg, algs)
		}
	}
}

func TestTokenPolicyRegistrationRules(t *testing.T) {
	t.Run("alg not enabled", func(t *testing.T) {
		a, _ := newASInstance(t, withTokenPolicy(&theauth.TokenPolicyConfig{SigningAlgs: []string{"ES256"}}))
		_, err := a.RegisterClient(context.Background(), theauth.ClientRegistrationRequest{
			RedirectURIs: []string{"https://app.example.com/cb"}, TokenEndpointAuthMethod: theauth.ClientAuthSecretBasic,
			AccessTokenSignedResponseAlg: "RS256",
		}, false)
		if err == nil {
			t.Fatal("RS256 is not enabled, registration must fail")
		}
	})
	t.Run("no policy configured", func(t *testing.T) {
		a, _ := newASInstance(t)
		_, err := a.RegisterClient(context.Background(), theauth.ClientRegistrationRequest{
			RedirectURIs: []string{"https://app.example.com/cb"}, TokenEndpointAuthMethod: theauth.ClientAuthSecretBasic,
			AccessTokenFormat: theauth.AccessTokenFormatOpaque,
		}, false)
		if err == nil {
			t.Fatal("opaque tokens are not enabled, registration must fail")
		}
	})
	t.Run("anonymous registrant", func(t *testing.T) {
		a, _ := newASInstance(t, withTokenPolicy(&theauth.TokenPolicyConfig{SigningAlgs: []string{"ES256"}}),
			func(c *theauth.AuthorizationServerConfig) { c.AllowAnonymousRegistration = true })
		_, err := a.RegisterClient(context.Background(), theauth.ClientRegistrationRequest{
			RedirectURIs: []string{"https://app.example.com/cb"}, TokenEndpointAuthMethod: theauth.ClientAuthNone,
			AccessTokenSignedResponseAlg: "ES256",
		}, true)
		if err == nil {
			t.Fatal("anonymous registrants must not set token policy")
		}
	})
	t.Run("unknown alg at config time", func(t *testing.T) {
		store := memory.New()
		_, err := theauth.New(theauth.Config{
			Storage: store, BaseURL: "https://auth.example.com", EncryptionKey: make([]byte, 32),
			AuthorizationServer: &theauth.AuthorizationServerConfig{
				Issuer:      "https://auth.example.com",
				TokenPolicy: &theauth.TokenPolicyConfig{SigningAlgs: []string{"HS256"}},
			},
		})
		if err == nil {
			t.Fatal("HS256 must be refused")
		}
	})
}

func TestOpaqueAccessTokens(t *testing.T) {
	a, store := newASInstance(t, withTokenPolicy(&theauth.TokenPolicyConfig{}))
	ctx := context.Background()
	client := registerPolicyClient(t, a, func(r *theauth.ClientRegistrationRequest) {
		r.AccessTokenFormat = theauth.AccessTokenFormatOpaque
	})
	tok, user := codeFlow(t, a, store, client, nil)
	if strings.Contains(tok.AccessToken, ".") {
		t.Fatalf("opaque token must not look like a JWT: %q", tok.AccessToken)
	}

	resp, _, err := a.IntrospectToken(ctx, tok.AccessToken, client.ClientID, client.ClientSecret, policyResource)
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Active || resp.Sub != user.ID.String() || resp.Aud != policyResource || resp.Scope != "files.read" {
		t.Fatalf("introspection: %+v", resp)
	}

	t.Run("wrong audience", func(t *testing.T) {
		r, _, _ := a.IntrospectToken(ctx, tok.AccessToken, client.ClientID, client.ClientSecret, "https://other.example.com")
		if r.Active {
			t.Fatal("audience mismatch must be inactive")
		}
	})

	t.Run("other client cannot revoke", func(t *testing.T) {
		other := registerPolicyClient(t, a, func(*theauth.ClientRegistrationRequest) {})
		if err := a.RevokeToken(ctx, tok.AccessToken, "access_token", other.ClientID, other.ClientSecret); err != nil {
			t.Fatal(err)
		}
		r, _, _ := a.IntrospectToken(ctx, tok.AccessToken, client.ClientID, client.ClientSecret, policyResource)
		if !r.Active {
			t.Fatal("a foreign client revoked the token")
		}
	})

	t.Run("revoke", func(t *testing.T) {
		if err := a.RevokeToken(ctx, tok.AccessToken, "access_token", client.ClientID, client.ClientSecret); err != nil {
			t.Fatal(err)
		}
		r, _, _ := a.IntrospectToken(ctx, tok.AccessToken, client.ClientID, client.ClientSecret, policyResource)
		if r.Active {
			t.Fatal("revoked opaque token must be inactive")
		}
	})

	t.Run("unknown token", func(t *testing.T) {
		r, _, _ := a.IntrospectToken(ctx, "bm90LWEtcmVhbC10b2tlbg", client.ClientID, client.ClientSecret, policyResource)
		if r.Active {
			t.Fatal("unknown token must be inactive")
		}
	})
}

func TestTokenPolicyDefaultFormatOpaque(t *testing.T) {
	a, store := newASInstance(t, withTokenPolicy(&theauth.TokenPolicyConfig{DefaultAccessTokenFormat: theauth.AccessTokenFormatOpaque}))
	client := registerPolicyClient(t, a, func(*theauth.ClientRegistrationRequest) {})
	tok, _ := codeFlow(t, a, store, client, nil)
	if strings.Contains(tok.AccessToken, ".") {
		t.Fatal("server default opaque must apply to clients that did not choose")
	}
}

func newUserID(t *testing.T, store *memory.Store) theauth.ULID {
	t.Helper()
	u := theauth.User{ID: ulid.New(), Email: "u" + ulid.New().String() + "@example.com"}
	if _, err := store.CreateUser(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	return u.ID
}

func authorizeReq(client theauth.RegisteredClient, details string) theauth.AuthorizeRequest {
	verifier, _ := crypto.NewCodeVerifier()
	return theauth.AuthorizeRequest{
		ClientID:             client.ClientID,
		RedirectURI:          "https://app.example.com/cb",
		ResponseType:         "code",
		Scope:                []string{"files.read"},
		CodeChallenge:        crypto.CodeChallenge(verifier),
		CodeChallengeMethod:  "S256",
		Resource:             policyResource,
		AuthorizationDetails: details,
	}
}

func TestDefaultSigningAlgRS256(t *testing.T) {
	a, store := newASInstance(t, func(c *theauth.AuthorizationServerConfig) { c.SigningAlg = "RS256" })
	client := registerPolicyClient(t, a, func(*theauth.ClientRegistrationRequest) {})
	tok, _ := codeFlow(t, a, store, client, nil)
	if got := jwtHeaderAlg(t, tok.AccessToken); got != "RS256" {
		t.Fatalf("alg %q, want RS256", got)
	}
	resp, _, err := a.IntrospectToken(context.Background(), tok.AccessToken, client.ClientID, client.ClientSecret, policyResource)
	if err != nil || !resp.Active {
		t.Fatalf("introspect: %v %v", resp.Active, err)
	}
}

func TestRotationCoversEveryAlgAndKeepsOldTokensValid(t *testing.T) {
	a, store := newASInstance(t, withTokenPolicy(&theauth.TokenPolicyConfig{SigningAlgs: []string{"ES256"}}))
	ctx := context.Background()
	client := registerPolicyClient(t, a, func(r *theauth.ClientRegistrationRequest) { r.AccessTokenSignedResponseAlg = "ES256" })
	before, _ := codeFlow(t, a, store, client, nil)

	if err := a.RotateSigningKey(ctx); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	keys, err := store.JWKSKeysAll(ctx)
	if err != nil {
		t.Fatal(err)
	}
	current := map[string]int{}
	for _, k := range keys {
		if k.State == theauth.JWKSStateCurrent {
			current[k.Alg]++
		}
	}
	if current["EdDSA"] != 1 || current["ES256"] != 1 {
		t.Fatalf("want exactly one current key per alg, got %v", current)
	}
	resp, _, err := a.IntrospectToken(ctx, before.AccessToken, client.ClientID, client.ClientSecret, policyResource)
	if err != nil || !resp.Active {
		t.Fatalf("a token signed before rotation must still verify: %v %v", resp.Active, err)
	}
	after, _ := codeFlow(t, a, store, client, nil)
	if jwtHeaderAlg(t, after.AccessToken) != "ES256" {
		t.Fatal("post rotation token lost the client's alg")
	}
}
