package as_test

// jwtbearer_test.go: tests for RFC 7523 JWT client authentication (section 2.2),
// the jwt-bearer grant type (section 2.1), and token-exchange polish.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/glincker/theauth-go"
	gocrypto "github.com/glincker/theauth-go/crypto"
	internalas "github.com/glincker/theauth-go/internal/as"
	"github.com/glincker/theauth-go/internal/models"
	"github.com/glincker/theauth-go/internal/ulid"
	"github.com/glincker/theauth-go/storage/memory"
)

// ---------- helpers ----------

// newJWTBearerASInstance wires an AS with JWTBearer enabled.
func newJWTBearerASInstance(t *testing.T, issuers []theauth.TrustedJWTIssuer) (*theauth.TheAuth, *memory.Store) {
	t.Helper()
	store := memory.New()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand: %v", err)
	}
	a, err := theauth.New(theauth.Config{
		Storage:       store,
		BaseURL:       "https://auth.example.com",
		EncryptionKey: key,
		AuthorizationServer: &theauth.AuthorizationServerConfig{
			Issuer:          "https://auth.example.com",
			Resources:       []theauth.ProtectedResource{{Identifier: "https://api.example.com/mcp", Scopes: []string{"api.read"}}},
			DisableRotation: true,
			JWTBearer: &theauth.JWTBearerConfig{
				TrustedJWTIssuers:     issuers,
				ClientAssertionMaxAge: 60 * time.Second,
				AssertionMaxAge:       300 * time.Second,
				ReplayCacheTTL:        600 * time.Second,
			},
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(a.Close)
	return a, store
}

// signJWT encodes header+payload and signs with ES256.
func signJWT(t *testing.T, priv *ecdsa.PrivateKey, header, payload map[string]any) string {
	t.Helper()
	hBytes, _ := json.Marshal(header)
	pBytes, _ := json.Marshal(payload)
	signingInput := base64.RawURLEncoding.EncodeToString(hBytes) + "." + base64.RawURLEncoding.EncodeToString(pBytes)
	h := sha256.New()
	h.Write([]byte(signingInput))
	digest := h.Sum(nil)
	sig, err := ecdsa.SignASN1(rand.Reader, priv, digest)
	if err != nil {
		t.Fatal(err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// buildClientAssertion mints an RFC 7523 section 2.2 client_assertion JWT.
func buildClientAssertion(t *testing.T, priv *ecdsa.PrivateKey, clientID, tokenEndpointURL, jti string, iat, exp time.Time) string {
	t.Helper()
	return signJWT(t, priv, map[string]any{"alg": "ES256", "typ": "JWT"}, map[string]any{
		"iss": clientID, "sub": clientID, "aud": tokenEndpointURL,
		"jti": jti, "iat": iat.Unix(), "exp": exp.Unix(),
	})
}

// buildBearerGrantAssertion mints an RFC 7523 section 2.1 assertion JWT.
func buildBearerGrantAssertion(t *testing.T, priv *ecdsa.PrivateKey, issuer, aud, sub, jti string, iat, exp time.Time) string {
	t.Helper()
	return signJWT(t, priv, map[string]any{"alg": "ES256", "typ": "JWT"}, map[string]any{
		"iss": issuer, "sub": sub, "aud": aud,
		"jti": jti, "iat": iat.Unix(), "exp": exp.Unix(),
	})
}

// jwksServerForECKey builds an httptest.Server serving a JWKS with the P-256 key.
func jwksServerForECKey(t *testing.T, pub *ecdsa.PublicKey) string {
	t.Helper()
	xBytes := pub.X.FillBytes(make([]byte, 32))
	yBytes := pub.Y.FillBytes(make([]byte, 32))
	jwk := map[string]any{
		"kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": "test-k1",
		"x": base64.RawURLEncoding.EncodeToString(xBytes),
		"y": base64.RawURLEncoding.EncodeToString(yBytes),
	}
	docBytes, _ := json.Marshal(map[string]any{"keys": []any{jwk}})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(docBytes)
	}))
	t.Cleanup(srv.Close)
	// Clear in-process JWKS cache so each test fetches fresh.
	internalas.ResetJWKSCache()
	return srv.URL + "/jwks"
}

// registerPKJWTClient inserts a client_secret-less client that authenticates
// via private_key_jwt.
func registerPKJWTClient(t *testing.T, store *memory.Store, jwksURI string) string {
	t.Helper()
	clientID := "pkjwt-" + ulid.New().String()
	client := theauth.OAuthClient{
		ID:                      ulid.New(),
		ClientID:                clientID,
		RedirectURIs:            []string{"https://app.example.com/cb"},
		GrantTypes:              []string{"authorization_code"},
		TokenEndpointAuthMethod: models.ClientAuthPrivateKeyJWT,
		JwksURI:                 jwksURI,
	}
	if _, err := store.InsertOAuthClient(context.Background(), client); err != nil {
		t.Fatalf("InsertOAuthClient: %v", err)
	}
	return clientID
}

// startAuthorizeAndGetCode issues an authorization code for the given client and user.
func startAuthorizeAndGetCode(t *testing.T, a *theauth.TheAuth, clientID string, user theauth.User) (code, verifier string) {
	t.Helper()
	v, err := gocrypto.NewCodeVerifier()
	if err != nil {
		t.Fatal(err)
	}
	res, err := a.StartAuthorize(context.Background(), theauth.AuthorizeRequest{
		ClientID:            clientID,
		RedirectURI:         "https://app.example.com/cb",
		ResponseType:        "code",
		Scope:               []string{"api.read"},
		CodeChallenge:       gocrypto.CodeChallenge(v),
		CodeChallengeMethod: "S256",
		Resource:            "https://api.example.com/mcp",
	}, &user)
	if err != nil {
		t.Fatalf("StartAuthorize: %v", err)
	}
	return codeFromRedirect(t, res.RedirectURL), v
}

// ---------- TestPrivateKeyJWTHappyPath ----------

// TestPrivateKeyJWTHappyPath: client authenticates with a signed ES256
// assertion instead of a client_secret; expects a valid access token.
func TestPrivateKeyJWTHappyPath(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwksURL := jwksServerForECKey(t, &priv.PublicKey)
	a, store := newJWTBearerASInstance(t, nil)
	clientID := registerPKJWTClient(t, store, jwksURL)

	ctx := context.Background()
	user := theauth.User{ID: ulid.New(), Email: "alice@example.com"}
	if _, err := store.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	code, verifier := startAuthorizeAndGetCode(t, a, clientID, user)

	now := time.Now()
	assertion := buildClientAssertion(t, priv, clientID, "https://auth.example.com/oauth/token",
		ulid.New().String(), now, now.Add(60*time.Second))

	resp, err := a.ExchangeAuthorizationCode(ctx, theauth.TokenRequest{
		GrantType:           "authorization_code",
		ClientID:            clientID,
		Code:                code,
		CodeVerifier:        verifier,
		RedirectURI:         "https://app.example.com/cb",
		ClientAssertionType: models.ClientAssertionTypeJWTBearer,
		ClientAssertion:     assertion,
	})
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode: %v", err)
	}
	if resp.AccessToken == "" {
		t.Fatal("expected non-empty access_token")
	}
}

// ---------- TestPrivateKeyJWTReplayRejected ----------

// TestPrivateKeyJWTReplayRejected: same jti used twice must fail on second attempt.
func TestPrivateKeyJWTReplayRejected(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwksURL := jwksServerForECKey(t, &priv.PublicKey)
	a, store := newJWTBearerASInstance(t, nil)
	clientID := registerPKJWTClient(t, store, jwksURL)
	ctx := context.Background()
	user := theauth.User{ID: ulid.New(), Email: "bob@example.com"}
	if _, err := store.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	jti := "replay-" + ulid.New().String()
	assertion := buildClientAssertion(t, priv, clientID, "https://auth.example.com/oauth/token",
		jti, now, now.Add(60*time.Second))

	// First use: must succeed.
	code1, v1 := startAuthorizeAndGetCode(t, a, clientID, user)
	_, err = a.ExchangeAuthorizationCode(ctx, theauth.TokenRequest{
		GrantType:           "authorization_code",
		ClientID:            clientID,
		Code:                code1,
		CodeVerifier:        v1,
		RedirectURI:         "https://app.example.com/cb",
		ClientAssertionType: models.ClientAssertionTypeJWTBearer,
		ClientAssertion:     assertion,
	})
	if err != nil {
		t.Fatalf("first exchange: %v", err)
	}

	// Second use of the same jti: must fail.
	code2, v2 := startAuthorizeAndGetCode(t, a, clientID, user)
	_, err = a.ExchangeAuthorizationCode(ctx, theauth.TokenRequest{
		GrantType:           "authorization_code",
		ClientID:            clientID,
		Code:                code2,
		CodeVerifier:        v2,
		RedirectURI:         "https://app.example.com/cb",
		ClientAssertionType: models.ClientAssertionTypeJWTBearer,
		ClientAssertion:     assertion,
	})
	if err == nil {
		t.Fatal("expected replay to be rejected")
	}
}

// ---------- TestPrivateKeyJWTExpiredAssertion ----------

func TestPrivateKeyJWTExpiredAssertion(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwksURL := jwksServerForECKey(t, &priv.PublicKey)
	a, store := newJWTBearerASInstance(t, nil)
	clientID := registerPKJWTClient(t, store, jwksURL)
	ctx := context.Background()
	user := theauth.User{ID: ulid.New(), Email: "charlie@example.com"}
	if _, err := store.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	code, verifier := startAuthorizeAndGetCode(t, a, clientID, user)

	past := time.Now().Add(-5 * time.Minute)
	expiredAssertion := buildClientAssertion(t, priv, clientID, "https://auth.example.com/oauth/token",
		ulid.New().String(), past.Add(-10*time.Second), past)

	_, err = a.ExchangeAuthorizationCode(ctx, theauth.TokenRequest{
		GrantType:           "authorization_code",
		ClientID:            clientID,
		Code:                code,
		CodeVerifier:        verifier,
		RedirectURI:         "https://app.example.com/cb",
		ClientAssertionType: models.ClientAssertionTypeJWTBearer,
		ClientAssertion:     expiredAssertion,
	})
	if err == nil {
		t.Fatal("expected expired assertion to be rejected")
	}
}

// ---------- TestPrivateKeyJWTWrongAudience ----------

func TestPrivateKeyJWTWrongAudience(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwksURL := jwksServerForECKey(t, &priv.PublicKey)
	a, store := newJWTBearerASInstance(t, nil)
	clientID := registerPKJWTClient(t, store, jwksURL)
	ctx := context.Background()
	user := theauth.User{ID: ulid.New(), Email: "dave@example.com"}
	if _, err := store.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	code, verifier := startAuthorizeAndGetCode(t, a, clientID, user)

	now := time.Now()
	badAudAssertion := buildClientAssertion(t, priv, clientID,
		"https://wrong-server.example.com/oauth/token", // wrong aud
		ulid.New().String(), now, now.Add(60*time.Second))

	_, err = a.ExchangeAuthorizationCode(ctx, theauth.TokenRequest{
		GrantType:           "authorization_code",
		ClientID:            clientID,
		Code:                code,
		CodeVerifier:        verifier,
		RedirectURI:         "https://app.example.com/cb",
		ClientAssertionType: models.ClientAssertionTypeJWTBearer,
		ClientAssertion:     badAudAssertion,
	})
	if err == nil {
		t.Fatal("expected wrong-aud assertion to be rejected")
	}
}

// ---------- TestPrivateKeyJWTAlgorithmDowngradeRejected ----------

// TestPrivateKeyJWTAlgorithmDowngradeRejected: HS256 not in the allowed
// set for private_key_jwt; must be rejected.
func TestPrivateKeyJWTAlgorithmDowngradeRejected(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwksURL := jwksServerForECKey(t, &priv.PublicKey)
	a, store := newJWTBearerASInstance(t, nil)
	clientID := registerPKJWTClient(t, store, jwksURL)
	ctx := context.Background()
	user := theauth.User{ID: ulid.New(), Email: "eve@example.com"}
	if _, err := store.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	code, verifier := startAuthorizeAndGetCode(t, a, clientID, user)

	now := time.Now()
	hBytes, _ := json.Marshal(map[string]any{"alg": "HS256", "typ": "JWT"})
	pBytes, _ := json.Marshal(map[string]any{
		"iss": clientID, "sub": clientID, "aud": "https://auth.example.com/oauth/token",
		"jti": ulid.New().String(), "iat": now.Unix(), "exp": now.Add(60 * time.Second).Unix(),
	})
	si := base64.RawURLEncoding.EncodeToString(hBytes) + "." + base64.RawURLEncoding.EncodeToString(pBytes)
	hs256Assertion := si + "." + base64.RawURLEncoding.EncodeToString([]byte("fakesig"))

	_, err = a.ExchangeAuthorizationCode(ctx, theauth.TokenRequest{
		GrantType:           "authorization_code",
		ClientID:            clientID,
		Code:                code,
		CodeVerifier:        verifier,
		RedirectURI:         "https://app.example.com/cb",
		ClientAssertionType: models.ClientAssertionTypeJWTBearer,
		ClientAssertion:     hs256Assertion,
	})
	if err == nil {
		t.Fatal("expected HS256 downgrade to be rejected for private_key_jwt client")
	}
}

// ---------- TestJWTBearerGrantHappyPath ----------

func TestJWTBearerGrantHappyPath(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwksURL := jwksServerForECKey(t, &priv.PublicKey)

	userID := ulid.New()
	issuers := []theauth.TrustedJWTIssuer{{
		Issuer:            "https://idp.example.com",
		JWKSURL:           jwksURL,
		AllowedAlgorithms: []string{"ES256"},
		SubjectMapper:     theauth.SubMapper{},
	}}
	a, _ := newJWTBearerASInstance(t, issuers)

	now := time.Now()
	assertion := buildBearerGrantAssertion(t, priv,
		"https://idp.example.com", "https://auth.example.com",
		userID.String(), ulid.New().String(), now, now.Add(5*time.Minute))

	resp, err := a.JWTBearerGrant(context.Background(), theauth.TokenRequest{
		GrantType: models.GrantTypeJWTBearer,
		Resource:  "https://api.example.com/mcp",
		Scope:     []string{"api.read"},
	}, assertion)
	if err != nil {
		t.Fatalf("JWTBearerGrant: %v", err)
	}
	if resp.AccessToken == "" {
		t.Fatal("expected non-empty access_token")
	}
}

// ---------- TestJWTBearerGrantUntrustedIssuer ----------

func TestJWTBearerGrantUntrustedIssuer(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwksURL := jwksServerForECKey(t, &priv.PublicKey)
	issuers := []theauth.TrustedJWTIssuer{{
		Issuer:        "https://trusted.example.com",
		JWKSURL:       jwksURL,
		SubjectMapper: theauth.SubMapper{},
	}}
	a, _ := newJWTBearerASInstance(t, issuers)

	now := time.Now()
	assertion := buildBearerGrantAssertion(t, priv,
		"https://untrusted.example.com", "https://auth.example.com",
		ulid.New().String(), ulid.New().String(), now, now.Add(5*time.Minute))

	_, err = a.JWTBearerGrant(context.Background(), theauth.TokenRequest{
		GrantType: models.GrantTypeJWTBearer,
		Resource:  "https://api.example.com/mcp",
		Scope:     []string{"api.read"},
	}, assertion)
	if err == nil {
		t.Fatal("expected untrusted issuer to be rejected")
	}
}

// ---------- TestJWTBearerGrantSubjectMapperMiss ----------

func TestJWTBearerGrantSubjectMapperMiss(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwksURL := jwksServerForECKey(t, &priv.PublicKey)
	issuers := []theauth.TrustedJWTIssuer{{
		Issuer:  "https://idp.example.com",
		JWKSURL: jwksURL,
		SubjectMapper: theauth.EmailMapper{
			Lookup: func(string) (theauth.ULID, error) {
				return theauth.ULID{}, theauth.ErrStorageNotFound
			},
		},
	}}
	a, _ := newJWTBearerASInstance(t, issuers)

	now := time.Now()
	assertion := signJWT(t, priv, map[string]any{"alg": "ES256", "typ": "JWT"}, map[string]any{
		"iss":   "https://idp.example.com",
		"sub":   "external-sub",
		"aud":   "https://auth.example.com",
		"email": "nobody@example.com",
		"jti":   ulid.New().String(),
		"iat":   now.Unix(),
		"exp":   now.Add(5 * time.Minute).Unix(),
	})

	_, err = a.JWTBearerGrant(context.Background(), theauth.TokenRequest{
		GrantType: models.GrantTypeJWTBearer,
		Resource:  "https://api.example.com/mcp",
		Scope:     []string{"api.read"},
	}, assertion)
	if err == nil {
		t.Fatal("expected subject mapper miss to produce error")
	}
}

// ---------- TestTokenExchangeMaxChainDepth ----------

// TestTokenExchangeMaxChainDepth: MaxActorChainDepth=1 means only one actor
// may be prepended. A second exchange on the resulting token must fail.
func TestTokenExchangeMaxChainDepth(t *testing.T) {
	// MaxActorChainDepth=2: depth counter starts at 1 (subject), so depth
	// becomes 2 after the first exchange (allowed) and 3 after the second
	// (3>2 => rejected). Net effect: exactly one actor may be prepended.
	a, store := newAgentASInstance(t, func(c *theauth.AuthorizationServerConfig) {
		c.JWTBearer = &theauth.JWTBearerConfig{MaxActorChainDepth: 2}
		c.AllowAnonymousRegistration = true
	})
	ctx := context.Background()
	user := theauth.User{ID: ulid.New(), Email: "frank@example.com"}
	if _, err := store.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}

	// Register client and get user token via authz code flow.
	reg, err := a.RegisterClient(ctx, theauth.ClientRegistrationRequest{
		RedirectURIs: []string{"https://app.example.com/cb"},
	}, true)
	if err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}
	verifier, _ := gocrypto.NewCodeVerifier()
	res, err := a.StartAuthorize(ctx, theauth.AuthorizeRequest{
		ClientID:            reg.ClientID,
		RedirectURI:         "https://app.example.com/cb",
		ResponseType:        "code",
		Scope:               []string{"files.read"},
		CodeChallenge:       gocrypto.CodeChallenge(verifier),
		CodeChallengeMethod: "S256",
		Resource:            "https://files.example.com/mcp",
	}, &user)
	if err != nil {
		t.Fatalf("StartAuthorize: %v", err)
	}
	userToken, err := a.ExchangeAuthorizationCode(ctx, theauth.TokenRequest{
		GrantType:    "authorization_code",
		ClientID:     reg.ClientID,
		ClientSecret: reg.ClientSecret,
		Code:         codeFromRedirect(t, res.RedirectURL),
		CodeVerifier: verifier,
		RedirectURI:  "https://app.example.com/cb",
	})
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode: %v", err)
	}

	ag1 := newAgentAndClient(t, a)
	ag2 := newAgentAndClient(t, a)
	grantDelegation(t, a, user.ID, ag1.AgentID)
	grantDelegation(t, a, user.ID, ag2.AgentID)

	// Depth 1: should succeed.
	first, err := a.ExchangeToken(ctx, theauth.TokenExchangeRequest{
		ClientID:         ag1.ClientID,
		ClientSecret:     ag1.Secret,
		SubjectToken:     userToken.AccessToken,
		SubjectTokenType: models.TokenTypeAccessToken,
		Resource:         "https://files.example.com/mcp",
	})
	if err != nil {
		t.Fatalf("first exchange: %v", err)
	}

	// Depth 2: exceeds MaxActorChainDepth=1, must fail.
	_, err = a.ExchangeToken(ctx, theauth.TokenExchangeRequest{
		ClientID:         ag2.ClientID,
		ClientSecret:     ag2.Secret,
		SubjectToken:     first.AccessToken,
		SubjectTokenType: models.TokenTypeAccessToken,
		Resource:         "https://files.example.com/mcp",
	})
	if err == nil {
		t.Fatal("expected chain depth exceeded error, got nil")
	}
}

// ---------- TestTokenExchangeAudienceWhitelist ----------

// TestTokenExchangeAudienceWhitelist: audience parameter must name a
// configured resource; unknown audience returns invalid_target.
func TestTokenExchangeAudienceWhitelist(t *testing.T) {
	a, store := newAgentASInstance(t, func(c *theauth.AuthorizationServerConfig) {
		c.AllowAnonymousRegistration = true
	})
	ctx := context.Background()
	user := theauth.User{ID: ulid.New(), Email: "grace@example.com"}
	if _, err := store.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}

	// Register a client and get a user token.
	reg, err := a.RegisterClient(ctx, theauth.ClientRegistrationRequest{
		RedirectURIs: []string{"https://app.example.com/cb"},
	}, true)
	if err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}
	userToken := authorizationCodeAccessToken(t, a, user, reg)
	ag := newAgentAndClient(t, a)
	grantDelegation(t, a, user.ID, ag.AgentID)

	_, err = a.ExchangeToken(ctx, theauth.TokenExchangeRequest{
		ClientID:         ag.ClientID,
		ClientSecret:     ag.Secret,
		SubjectToken:     userToken,
		SubjectTokenType: models.TokenTypeAccessToken,
		Resource:         "https://files.example.com/mcp",
		Audience:         "https://unknown.example.com", // not in Resources
	})
	if err == nil {
		t.Fatal("expected unknown audience to be rejected with invalid_target")
	}
}
