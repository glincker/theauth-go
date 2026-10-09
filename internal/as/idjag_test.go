package as_test

// idjag_test.go: Identity Assertion JWT Authorization Grant, both halves.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/internal/models"
	"github.com/glincker/theauth-go/v2/internal/ulid"
	"github.com/glincker/theauth-go/v2/storage/memory"
)

const (
	jagResource = "https://api.example.com/mcp"
	jagAudience = "https://rs-as.example.com"
	jagIDP      = "https://idp.example.com"
)

func newIDJAGInstance(t *testing.T, jag *theauth.IDJAGConfig, issuers []theauth.TrustedJWTIssuer) (*theauth.TheAuth, *memory.Store) {
	t.Helper()
	store := memory.New()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	cfg := &theauth.AuthorizationServerConfig{
		Issuer:          "https://auth.example.com",
		Resources:       []theauth.ProtectedResource{{Identifier: jagResource, Scopes: []string{"api.read", "api.write"}}},
		DisableRotation: true,
		IDJAG:           jag,
	}
	if issuers != nil {
		cfg.JWTBearer = &theauth.JWTBearerConfig{
			TrustedJWTIssuers: issuers, AllowPrivateJWKSNetworks: true,
			ClientAssertionMaxAge: time.Minute, AssertionMaxAge: 5 * time.Minute, ReplayCacheTTL: 10 * time.Minute,
		}
	}
	a, err := theauth.New(theauth.Config{
		Storage: store, BaseURL: "https://auth.example.com", EncryptionKey: key, AuthorizationServer: cfg,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(a.Close)
	return a, store
}

func jagTweak(scope ...string) func(*theauth.AuthorizeRequest) {
	return func(r *theauth.AuthorizeRequest) { r.Resource = jagResource; r.Scope = scope }
}

func decodeJWTPart(t *testing.T, token string, idx int) map[string]any {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(strings.Split(token, ".")[idx])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestIDJAGIssue(t *testing.T) {
	a, store := newIDJAGInstance(t, &theauth.IDJAGConfig{Audiences: []string{jagAudience}}, nil)
	ctx := context.Background()
	client := confidentialClient(t, a)
	subject, user := codeFlow(t, a, store, client, jagTweak("api.read", "api.write"))

	exchange := func(mut func(*theauth.TokenExchangeRequest)) (theauth.TokenResponse, error) {
		req := theauth.TokenExchangeRequest{
			ClientID: client.ClientID, ClientSecret: client.ClientSecret,
			SubjectToken: subject.AccessToken, SubjectTokenType: theauth.TokenTypeAccessToken,
			RequestedTokenType: theauth.TokenTypeIDJAG, Audience: jagAudience,
			Resource: "https://rs.example.com/api", Scope: []string{"api.read"},
		}
		if mut != nil {
			mut(&req)
		}
		return a.ExchangeToken(ctx, req)
	}

	t.Run("issues an assertion", func(t *testing.T) {
		resp, err := exchange(nil)
		if err != nil {
			t.Fatal(err)
		}
		if resp.IssuedTokenType != theauth.TokenTypeIDJAG || resp.TokenType != "N_A" {
			t.Fatalf("response: %+v", resp)
		}
		hdr := decodeJWTPart(t, resp.AccessToken, 0)
		if hdr["typ"] != "oauth-id-jag+jwt" || hdr["alg"] != "EdDSA" || hdr["kid"] == "" {
			t.Fatalf("header: %v", hdr)
		}
		c := decodeJWTPart(t, resp.AccessToken, 1)
		if c["iss"] != "https://auth.example.com" || c["sub"] != user.ID.String() || c["aud"] != jagAudience ||
			c["client_id"] != client.ClientID || c["scope"] != "api.read" || c["resource"] != "https://rs.example.com/api" || c["jti"] == "" {
			t.Fatalf("claims: %v", c)
		}
		if ttl := c["exp"].(float64) - c["iat"].(float64); ttl <= 0 || ttl > 300 {
			t.Fatalf("ttl %v", ttl)
		}
		if resp.ExpiresIn <= 0 || resp.ExpiresIn > 300 {
			t.Fatalf("expires_in %d", resp.ExpiresIn)
		}
	})
	t.Run("audience must be allowed", func(t *testing.T) {
		_, err := exchange(func(r *theauth.TokenExchangeRequest) { r.Audience = "https://evil.example.com" })
		if !errors.Is(err, theauth.ErrOAuthInvalidResource) {
			t.Fatalf("got %v", err)
		}
		_, err = exchange(func(r *theauth.TokenExchangeRequest) { r.Audience = "" })
		if !errors.Is(err, theauth.ErrOAuthInvalidResource) {
			t.Fatalf("missing audience: got %v", err)
		}
	})
	t.Run("scope cannot widen", func(t *testing.T) {
		narrow, _ := codeFlow(t, a, store, client, jagTweak("api.read"))
		_, err := exchange(func(r *theauth.TokenExchangeRequest) {
			r.SubjectToken = narrow.AccessToken
			r.Scope = []string{"api.write"}
		})
		if !errors.Is(err, theauth.ErrOAuthInvalidScope) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("subject must belong to the client", func(t *testing.T) {
		other := confidentialClient(t, a)
		tok, _ := codeFlow(t, a, store, other, jagTweak("api.read"))
		_, err := exchange(func(r *theauth.TokenExchangeRequest) { r.SubjectToken = tok.AccessToken })
		if err == nil {
			t.Fatal("a token issued to another client must not be exchangeable")
		}
	})
	t.Run("bad subject and client secret", func(t *testing.T) {
		if _, err := exchange(func(r *theauth.TokenExchangeRequest) { r.SubjectToken = "x.y.z" }); err == nil {
			t.Fatal("garbage subject token accepted")
		}
		if _, err := exchange(func(r *theauth.TokenExchangeRequest) { r.ClientSecret = "wrong" }); err == nil {
			t.Fatal("wrong client secret accepted")
		}
	})
}

func TestIDJAGDisabledByDefault(t *testing.T) {
	a, store := newIDJAGInstance(t, nil, nil)
	client := confidentialClient(t, a)
	subject, _ := codeFlow(t, a, store, client, jagTweak("api.read"))
	_, err := a.ExchangeToken(context.Background(), theauth.TokenExchangeRequest{
		ClientID: client.ClientID, ClientSecret: client.ClientSecret, SubjectToken: subject.AccessToken,
		RequestedTokenType: theauth.TokenTypeIDJAG, Audience: jagAudience,
	})
	if !errors.Is(err, theauth.ErrOAuthUnsupportedGrantType) {
		t.Fatalf("got %v", err)
	}
}

func TestIDJAGConfigValidation(t *testing.T) {
	for _, bad := range []*theauth.IDJAGConfig{
		{Audiences: []string{"http://insecure.example.com"}},
		{Audiences: []string{"not a url"}},
		{Audiences: []string{jagAudience}, TTL: time.Hour},
	} {
		store := memory.New()
		_, err := theauth.New(theauth.Config{
			Storage: store, BaseURL: "https://auth.example.com", EncryptionKey: make([]byte, 32),
			AuthorizationServer: &theauth.AuthorizationServerConfig{Issuer: "https://auth.example.com", IDJAG: bad},
		})
		if err == nil {
			t.Fatalf("config %+v accepted", bad)
		}
	}
}

// jagAssertion signs an ID-JAG as the trusted IdP would.
func jagAssertion(t *testing.T, priv *ecdsa.PrivateKey, typ string, mut func(map[string]any)) string {
	t.Helper()
	now := time.Now()
	claims := map[string]any{
		"iss": jagIDP, "sub": ulid.New().String(), "aud": "https://auth.example.com",
		"jti": ulid.New().String(), "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
		"client_id": "", "scope": "api.read", "resource": jagResource,
	}
	mut(claims)
	return signJWT(t, priv, map[string]any{"alg": "ES256", "typ": typ}, claims)
}

func TestIDJAGRedeem(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuers := []theauth.TrustedJWTIssuer{{
		Issuer: jagIDP, JWKSURL: jwksServerForECKey(t, &priv.PublicKey),
		AllowedAlgorithms: []string{"ES256"}, SubjectMapper: theauth.SubMapper{},
	}}
	a, _ := newIDJAGInstance(t, &theauth.IDJAGConfig{}, issuers)
	client := confidentialClient(t, a)
	ctx := context.Background()

	redeem := func(assertion string, mut func(*theauth.TokenRequest)) (theauth.TokenResponse, error) {
		req := theauth.TokenRequest{
			GrantType: models.GrantTypeJWTBearer, ClientID: client.ClientID, ClientSecret: client.ClientSecret,
			Resource: jagResource, Scope: []string{"api.read"}, Assertion: assertion,
		}
		if mut != nil {
			mut(&req)
		}
		return a.JWTBearerGrant(ctx, req, assertion)
	}
	good := func(c map[string]any) { c["client_id"] = client.ClientID }

	t.Run("redeems", func(t *testing.T) {
		resp, err := redeem(jagAssertion(t, priv, "oauth-id-jag+jwt", good), nil)
		if err != nil {
			t.Fatal(err)
		}
		if resp.Scope != "api.read" || resp.AccessToken == "" {
			t.Fatalf("response: %+v", resp)
		}
	})
	t.Run("scope defaults to the assertion", func(t *testing.T) {
		resp, err := redeem(jagAssertion(t, priv, "oauth-id-jag+jwt", good), func(r *theauth.TokenRequest) { r.Scope = nil })
		if err != nil || resp.Scope != "api.read" {
			t.Fatalf("got %+v %v", resp, err)
		}
	})
	t.Run("client_id must match the authenticated client", func(t *testing.T) {
		_, err := redeem(jagAssertion(t, priv, "oauth-id-jag+jwt", func(c map[string]any) { c["client_id"] = "someone-else" }), nil)
		if err == nil {
			t.Fatal("assertion for another client accepted")
		}
	})
	t.Run("client must authenticate", func(t *testing.T) {
		_, err := redeem(jagAssertion(t, priv, "oauth-id-jag+jwt", good), func(r *theauth.TokenRequest) { r.ClientSecret = "wrong" })
		if err == nil {
			t.Fatal("unauthenticated redemption accepted")
		}
	})
	t.Run("scope cannot exceed the assertion", func(t *testing.T) {
		_, err := redeem(jagAssertion(t, priv, "oauth-id-jag+jwt", good), func(r *theauth.TokenRequest) { r.Scope = []string{"api.write"} })
		if !errors.Is(err, theauth.ErrOAuthInvalidScope) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("resource must match", func(t *testing.T) {
		_, err := redeem(jagAssertion(t, priv, "oauth-id-jag+jwt", func(c map[string]any) {
			good(c)
			c["resource"] = "https://other.example.com/mcp"
		}), nil)
		if err == nil {
			t.Fatal("resource mismatch accepted")
		}
	})
	t.Run("replay", func(t *testing.T) {
		assertion := jagAssertion(t, priv, "oauth-id-jag+jwt", good)
		if _, err := redeem(assertion, nil); err != nil {
			t.Fatal(err)
		}
		if _, err := redeem(assertion, nil); err == nil {
			t.Fatal("replayed assertion accepted")
		}
	})
	t.Run("jti is required", func(t *testing.T) {
		_, err := redeem(jagAssertion(t, priv, "oauth-id-jag+jwt", func(c map[string]any) { good(c); delete(c, "jti") }), nil)
		if err == nil {
			t.Fatal("assertion without jti accepted")
		}
	})
}

func TestIDJAGRedeemNeedsConfig(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	issuers := []theauth.TrustedJWTIssuer{{
		Issuer: jagIDP, JWKSURL: jwksServerForECKey(t, &priv.PublicKey),
		AllowedAlgorithms: []string{"ES256"}, SubjectMapper: theauth.SubMapper{},
	}}
	a, _ := newIDJAGInstance(t, nil, issuers)
	client := confidentialClient(t, a)
	assertion := jagAssertion(t, priv, "oauth-id-jag+jwt", func(c map[string]any) { c["client_id"] = client.ClientID })
	_, err := a.JWTBearerGrant(context.Background(), theauth.TokenRequest{
		GrantType: models.GrantTypeJWTBearer, ClientID: client.ClientID, ClientSecret: client.ClientSecret,
		Resource: jagResource, Scope: []string{"api.read"},
	}, assertion)
	if err == nil {
		t.Fatal("an id-jag must be refused when IDJAG is not enabled")
	}
}
