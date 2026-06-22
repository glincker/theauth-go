package as_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/crypto"
	"github.com/glincker/theauth-go/internal/ulid"
	"github.com/glincker/theauth-go/mcpresource"
	"github.com/glincker/theauth-go/storage/memory"
	"github.com/go-chi/chi/v5"
)

// e2e_dpop_test.go: full RFC 9449 round trip through the real AS and
// the real mcpresource middleware. Verifies that:
//
//  1. The token endpoint accepts a DPoP header, returns token_type=DPoP,
//     and the issued JWT carries cnf.jkt matching the proof thumbprint.
//  2. mcpresource accepts the same token + a fresh proof signed by the
//     bound key.
//  3. mcpresource rejects an inbound proof signed by a different key
//     (stolen-token defense).
//  4. The .well-known/oauth-authorization-server metadata advertises
//     dpop_signing_alg_values_supported when DPoP is enabled.
func TestDPoPEndToEnd(t *testing.T) {
	a, srv, user := newDPoPHarness(t)
	defer srv.Close()
	clientPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	client := registerTestClient(t, srv)
	verifier, _ := crypto.NewCodeVerifier()
	res, err := a.StartAuthorize(context.Background(), theauth.AuthorizeRequest{
		ClientID:            client.ClientID,
		RedirectURI:         "https://app.example.com/cb",
		ResponseType:        "code",
		Scope:               []string{"files.read"},
		CodeChallenge:       crypto.CodeChallenge(verifier),
		CodeChallengeMethod: "S256",
		Resource:            "https://files.example.com/mcp",
	}, &user)
	if err != nil {
		t.Fatalf("StartAuthorize: %v", err)
	}
	code := codeFromRedirect(t, res.RedirectURL)

	// POST /oauth/token with a DPoP header.
	tokenURL := srv.URL + "/oauth/token"
	proofTokenEndpoint := makeDPoPProof(t, clientPriv, "POST", tokenURL, "", time.Now())
	form := url.Values{}
	form.Set("grant_type", theauth.GrantTypeAuthorizationCode)
	form.Set("client_id", client.ClientID)
	form.Set("client_secret", client.ClientSecret)
	form.Set("code", code)
	form.Set("code_verifier", verifier)
	form.Set("redirect_uri", "https://app.example.com/cb")
	req, _ := http.NewRequest(http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("DPoP", proofTokenEndpoint)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("token POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token endpoint status %d body=%s", resp.StatusCode, raw)
	}
	var tokResp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}
	if err := json.Unmarshal(raw, &tokResp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if tokResp.TokenType != "DPoP" {
		t.Fatalf("token_type=%q want DPoP", tokResp.TokenType)
	}

	// Decode the access token payload and confirm cnf.jkt matches the
	// thumbprint of the key we signed the proof with.
	parts := strings.Split(tokResp.AccessToken, ".")
	if len(parts) != 3 {
		t.Fatalf("malformed access token")
	}
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var claims map[string]any
	_ = json.Unmarshal(payload, &claims)
	cnf, _ := claims["cnf"].(map[string]any)
	jktClaim, _ := cnf["jkt"].(string)
	wantThumb := jwkThumbprintES256(t, clientPriv)
	if jktClaim != wantThumb {
		t.Fatalf("cnf.jkt=%q want %q", jktClaim, wantThumb)
	}

	// Bring up the real mcpresource validator pointed at the AS JWKS.
	v := mcpresource.New(
		"https://files.example.com/mcp",
		mcpresource.WithJWKS(srv.URL+"/oauth/jwks"),
		mcpresource.WithDPoPVerification(nil, 0, 0),
	)
	// Happy path: serve a request whose DPoP proof is signed by the
	// bound key and references the access token.
	mcpURL := "https://files.example.com/mcp/x"
	mcpProof := makeDPoPProof(t, clientPriv, "GET", mcpURL, tokResp.AccessToken, time.Now())
	rec := httptest.NewRecorder()
	mcpReq := httptest.NewRequest(http.MethodGet, mcpURL, nil)
	mcpReq.Header.Set("Authorization", "DPoP "+tokResp.AccessToken)
	mcpReq.Header.Set("DPoP", mcpProof)
	called := false
	v.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })).ServeHTTP(rec, mcpReq)
	if rec.Code != http.StatusOK {
		t.Fatalf("mcp resource want 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if !called {
		t.Fatalf("inner handler not invoked")
	}

	// Stolen-token defense: same access token, but proof signed with a
	// foreign key.
	thiefPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	thiefProof := makeDPoPProof(t, thiefPriv, "GET", mcpURL, tokResp.AccessToken, time.Now())
	rec2 := httptest.NewRecorder()
	mcpReq2 := httptest.NewRequest(http.MethodGet, mcpURL, nil)
	mcpReq2.Header.Set("Authorization", "DPoP "+tokResp.AccessToken)
	mcpReq2.Header.Set("DPoP", thiefProof)
	v.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("stolen-token call must not reach handler")
	})).ServeHTTP(rec2, mcpReq2)
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("stolen-token want 401 got %d", rec2.Code)
	}

	// Metadata advertises DPoP algs.
	mdResp, err := http.Get(srv.URL + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatalf("metadata: %v", err)
	}
	defer func() { _ = mdResp.Body.Close() }()
	var md map[string]any
	_ = json.NewDecoder(mdResp.Body).Decode(&md)
	algs, ok := md["dpop_signing_alg_values_supported"].([]any)
	if !ok || len(algs) == 0 {
		t.Fatalf("metadata missing dpop_signing_alg_values_supported: %v", md)
	}
}

// newDPoPHarness builds a TheAuth with DPoP enabled, mounts it on a chi
// router, and returns the live test server + the seeded user.
func newDPoPHarness(t *testing.T) (*theauth.TheAuth, *httptest.Server, theauth.User) {
	t.Helper()
	store := memory.New()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	asCfg := &theauth.AuthorizationServerConfig{
		Issuer:             "https://auth.example.com",
		Resources:          []theauth.ProtectedResource{{Identifier: "https://files.example.com/mcp", Scopes: []string{"files.read"}}},
		RegistrationTokens: []string{"initial-access-token"},
		DisableRotation:    true,
		DPoP:               &theauth.DPoPConfig{},
	}
	a, err := theauth.New(theauth.Config{
		Storage:             store,
		BaseURL:             "https://auth.example.com",
		EncryptionKey:       key,
		AuthorizationServer: asCfg,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(a.Close)
	user := theauth.User{ID: ulid.New(), Email: "alice@example.com"}
	if _, err := store.CreateUser(context.Background(), user); err != nil {
		t.Fatal(err)
	}
	r := chi.NewRouter()
	a.Mount(r)
	srv := httptest.NewServer(r)
	return a, srv, user
}

var dpopE2EJTI int64

// makeDPoPProof signs a valid DPoP proof JWT for the supplied params.
// Returns the compact JWT.
func makeDPoPProof(t *testing.T, priv *ecdsa.PrivateKey, method, urlStr, accessToken string, iat time.Time) string {
	t.Helper()
	jwk := map[string]string{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(priv.X.Bytes()),
		"y":   base64.RawURLEncoding.EncodeToString(priv.Y.Bytes()),
	}
	header := map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": jwk}
	dpopE2EJTI++
	claims := map[string]any{
		"jti": fmt.Sprintf("e2e-jti-%d-%d", iat.UnixNano(), dpopE2EJTI),
		"htm": method,
		"htu": urlStr,
		"iat": iat.Unix(),
	}
	if accessToken != "" {
		sum := sha256.Sum256([]byte(accessToken))
		claims["ath"] = base64.RawURLEncoding.EncodeToString(sum[:])
	}
	headerJSON, _ := json.Marshal(header)
	payloadJSON, _ := json.Marshal(claims)
	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(payloadJSON)
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatalf("ecdsa sign: %v", err)
	}
	const byteSize = 32
	sig := make([]byte, 2*byteSize)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sig[byteSize-len(rBytes):], rBytes)
	copy(sig[2*byteSize-len(sBytes):], sBytes)
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func jwkThumbprintES256(t *testing.T, priv *ecdsa.PrivateKey) string {
	t.Helper()
	x := base64.RawURLEncoding.EncodeToString(priv.X.Bytes())
	y := base64.RawURLEncoding.EncodeToString(priv.Y.Bytes())
	canonical := fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":%q,"y":%q}`, x, y)
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
