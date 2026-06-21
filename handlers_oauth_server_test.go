package theauth_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/crypto"
	"github.com/glincker/theauth-go/internal/ulid"
	"github.com/go-chi/chi/v5"
)

// newASHarness wires a TheAuth instance with an AS, a chi router, and a
// helper for stamping a session cookie carrying a known user. Returns the
// instance, the test server, and the user / session token pair so tests can
// drive the authorize endpoint with an authenticated principal.
func newASHarness(t *testing.T) (*theauth.TheAuth, *httptest.Server, theauth.User, string) {
	t.Helper()
	a, store := newASInstance(t)
	user := theauth.User{ID: ulid.New(), Email: "alice@example.com"}
	if _, err := store.CreateUser(context.Background(), user); err != nil {
		t.Fatal(err)
	}
	rawToken, err := crypto.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	hash := crypto.HashToken(rawToken)
	sess := theauth.Session{
		ID:        ulid.New(),
		UserID:    user.ID,
		TokenHash: hash,
		AuthLevel: theauth.AuthLevelFull,
	}
	// Far-future expiry so handler treats it as live.
	sess.ExpiresAt = sess.ExpiresAt.Add(0)
	if _, err := store.CreateSession(context.Background(), sess); err != nil {
		t.Fatal(err)
	}
	// Set ExpiresAt explicitly via a re-insert: CreateSession in the memory
	// adapter takes the struct as-is.
	r := chi.NewRouter()
	a.Mount(r)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return a, srv, user, rawToken
}

func TestASMetadataDocumentShape(t *testing.T) {
	_, srv, _, _ := newASHarness(t)
	resp, err := http.Get(srv.URL + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	mustContain := []string{"issuer", "authorization_endpoint", "token_endpoint", "jwks_uri", "code_challenge_methods_supported"}
	for _, k := range mustContain {
		if _, ok := doc[k]; !ok {
			t.Fatalf("metadata missing %q: %v", k, doc)
		}
	}
	// Verify S256-only advertisement (downgrade prevention).
	methods, _ := doc["code_challenge_methods_supported"].([]any)
	if len(methods) != 1 || methods[0] != "S256" {
		t.Fatalf("expected S256-only methods, got %v", methods)
	}
}

func TestJWKSEndpointServesEd25519Keys(t *testing.T) {
	_, srv, _, _ := newASHarness(t)
	resp, err := http.Get(srv.URL + "/oauth/jwks")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var doc struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Keys) < 2 {
		t.Fatalf("expected >= 2 keys, got %d", len(doc.Keys))
	}
	for _, k := range doc.Keys {
		if k["kty"] != "OKP" || k["crv"] != "Ed25519" || k["alg"] != "EdDSA" {
			t.Fatalf("jwks key shape: %v", k)
		}
	}
}

func TestDCRBearerGatedDenialAndAnonymousFlag(t *testing.T) {
	a, srv, _, _ := newASHarness(t)
	// Anonymous (no bearer) call against an AS where anonymous registration
	// is disabled (default) returns 401 access_denied.
	body := `{"redirect_uris":["https://app.example.com/cb"]}`
	resp, err := http.Post(srv.URL+"/oauth/register", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
	_ = a

	// Bearer-gated path: any non-empty Bearer token is accepted in phase 1+2.
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/oauth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer initial-access-token")
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp2.Body.Close() }()
	if resp2.StatusCode != http.StatusCreated {
		buf, _ := io.ReadAll(resp2.Body)
		t.Fatalf("expected 201, got %d body=%s", resp2.StatusCode, buf)
	}
	var reg theauth.RegisteredClient
	if err := json.NewDecoder(resp2.Body).Decode(&reg); err != nil {
		t.Fatal(err)
	}
	if reg.ClientID == "" || reg.ClientSecret == "" {
		t.Fatalf("client registration response missing fields: %+v", reg)
	}
}

func TestAnonymousRegistrationWhenEnabled(t *testing.T) {
	a, store := newASInstance(t, func(c *theauth.AuthorizationServerConfig) {
		c.AllowAnonymousRegistration = true
	})
	r := chi.NewRouter()
	a.Mount(r)
	srv := httptest.NewServer(r)
	defer srv.Close()
	body := `{"redirect_uris":["https://app.example.com/cb"]}`
	resp, err := http.Post(srv.URL+"/oauth/register", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		buf, _ := io.ReadAll(resp.Body)
		t.Fatalf("anonymous registration failed: status=%d body=%s", resp.StatusCode, buf)
	}
	var reg theauth.RegisteredClient
	_ = json.NewDecoder(resp.Body).Decode(&reg)
	// Anonymous clients are public (no client_secret) per spec section 9.10.
	if reg.ClientSecret != "" {
		t.Fatalf("anonymous registration must produce public client, got secret")
	}
	// AnonymousRegistered flag must be set on the stored row.
	stored, err := store.OAuthClientByClientID(context.Background(), reg.ClientID)
	if err != nil {
		t.Fatal(err)
	}
	if !stored.AnonymousRegistered {
		t.Fatal("expected stored client to carry AnonymousRegistered=true")
	}
}

func TestAuthorizeRejectsMissingPKCE(t *testing.T) {
	_, srv, _, _ := newASHarness(t)
	client := registerTestClient(t, srv)
	u, _ := url.Parse(srv.URL + "/oauth/authorize")
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", client.ClientID)
	q.Set("redirect_uri", "https://app.example.com/cb")
	q.Set("scope", "files.read")
	q.Set("resource", "https://files.example.com/mcp")
	// deliberately omit code_challenge.
	u.RawQuery = q.Encode()
	httpC := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := httpC.Get(u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 invalid_request, got %d", resp.StatusCode)
	}
}

func TestAuthorizeRejectsBadResource(t *testing.T) {
	_, srv, _, _ := newASHarness(t)
	client := registerTestClient(t, srv)
	verifier, _ := crypto.NewCodeVerifier()
	u, _ := url.Parse(srv.URL + "/oauth/authorize")
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", client.ClientID)
	q.Set("redirect_uri", "https://app.example.com/cb")
	q.Set("scope", "files.read")
	q.Set("resource", "https://other.example.com/mcp")
	q.Set("code_challenge", crypto.CodeChallenge(verifier))
	q.Set("code_challenge_method", "S256")
	u.RawQuery = q.Encode()
	httpC := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := httpC.Get(u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

// registerTestClient uses the bearer-gated DCR path to mint a client with
// the test redirect URI.
func registerTestClient(t *testing.T, srv *httptest.Server) theauth.RegisteredClient {
	t.Helper()
	body := `{"redirect_uris":["https://app.example.com/cb"]}`
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/oauth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer initial-access-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("registerTestClient: status %d", resp.StatusCode)
	}
	var reg theauth.RegisteredClient
	if err := json.NewDecoder(resp.Body).Decode(&reg); err != nil {
		t.Fatal(err)
	}
	return reg
}

// tokenDispatchFixture builds a fully wired AS via httptest.NewServer, seeds
// a user + confidential client, and returns the live PKCE verifier so callers
// can drive the authorization_code flow end to end against the HTTP token
// endpoint. Every grant-type test below reuses this harness so the table is
// exercising the real form-parser plus the real client-credential extractor.
type tokenDispatchFixture struct {
	auth     *theauth.TheAuth
	server   *httptest.Server
	user     theauth.User
	client   theauth.RegisteredClient
	verifier string
	code     string
}

func newTokenDispatchFixture(t *testing.T) *tokenDispatchFixture {
	t.Helper()
	a, srv, user, _ := newASHarness(t)
	client := registerTestClient(t, srv)
	verifier, err := crypto.NewCodeVerifier()
	if err != nil {
		t.Fatal(err)
	}
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
	return &tokenDispatchFixture{
		auth:     a,
		server:   srv,
		user:     user,
		client:   client,
		verifier: verifier,
		code:     code,
	}
}

// postForm POSTs a form-encoded body to /oauth/token and decodes the JSON
// response shape. The caller asserts against status + body fields.
func postForm(t *testing.T, srv *httptest.Server, form url.Values, decorate func(*http.Request)) (*http.Response, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/oauth/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if decorate != nil {
		decorate(req)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]any{}
	if len(body) > 0 {
		if jerr := json.Unmarshal(body, &out); jerr != nil {
			t.Fatalf("decode body %q: %v", body, jerr)
		}
	}
	return resp, out
}

// TestHandleTokenDispatch drives /oauth/token via httptest.NewServer for
// every grant type (authorization_code, refresh_token, client_credentials,
// urn:ietf:params:oauth:grant-type:token-exchange) plus every documented
// error path (malformed form, missing grant_type, unsupported grant type,
// bad client auth, malformed inputs). The table is intentionally exhaustive
// because handleToken itself is the single largest 0%-coverage function
// in the v2.0 surface per the 2026-06-20 audit.
func TestHandleTokenDispatch(t *testing.T) {
	t.Run("authorization_code_happy_path", func(t *testing.T) {
		fx := newTokenDispatchFixture(t)
		form := url.Values{}
		form.Set("grant_type", theauth.GrantTypeAuthorizationCode)
		form.Set("client_id", fx.client.ClientID)
		form.Set("client_secret", fx.client.ClientSecret)
		form.Set("code", fx.code)
		form.Set("code_verifier", fx.verifier)
		form.Set("redirect_uri", "https://app.example.com/cb")
		resp, body := postForm(t, fx.server, form, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status=%d body=%v", resp.StatusCode, body)
		}
		if got, _ := body["access_token"].(string); got == "" {
			t.Fatalf("missing access_token in %v", body)
		}
		if got := resp.Header.Get("Cache-Control"); got != "no-store" {
			t.Errorf("Cache-Control=%q, want no-store", got)
		}
		if got := resp.Header.Get("Pragma"); got != "no-cache" {
			t.Errorf("Pragma=%q, want no-cache", got)
		}
		if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type=%q, want application/json", ct)
		}
	})

	t.Run("authorization_code_basic_auth", func(t *testing.T) {
		fx := newTokenDispatchFixture(t)
		form := url.Values{}
		form.Set("grant_type", theauth.GrantTypeAuthorizationCode)
		form.Set("code", fx.code)
		form.Set("code_verifier", fx.verifier)
		form.Set("redirect_uri", "https://app.example.com/cb")
		resp, body := postForm(t, fx.server, form, func(r *http.Request) {
			r.SetBasicAuth(fx.client.ClientID, fx.client.ClientSecret)
		})
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status=%d body=%v", resp.StatusCode, body)
		}
	})

	t.Run("authorization_code_pkce_mismatch", func(t *testing.T) {
		fx := newTokenDispatchFixture(t)
		wrong, _ := crypto.NewCodeVerifier()
		form := url.Values{}
		form.Set("grant_type", theauth.GrantTypeAuthorizationCode)
		form.Set("client_id", fx.client.ClientID)
		form.Set("client_secret", fx.client.ClientSecret)
		form.Set("code", fx.code)
		form.Set("code_verifier", wrong)
		form.Set("redirect_uri", "https://app.example.com/cb")
		resp, body := postForm(t, fx.server, form, nil)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status=%d body=%v", resp.StatusCode, body)
		}
		if body["error"] != theauth.OAuthErrInvalidGrant {
			t.Errorf("error=%v, want invalid_grant", body["error"])
		}
	})

	t.Run("authorization_code_redirect_uri_mismatch", func(t *testing.T) {
		fx := newTokenDispatchFixture(t)
		form := url.Values{}
		form.Set("grant_type", theauth.GrantTypeAuthorizationCode)
		form.Set("client_id", fx.client.ClientID)
		form.Set("client_secret", fx.client.ClientSecret)
		form.Set("code", fx.code)
		form.Set("code_verifier", fx.verifier)
		form.Set("redirect_uri", "https://other.example.com/cb")
		resp, body := postForm(t, fx.server, form, nil)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status=%d body=%v", resp.StatusCode, body)
		}
		if body["error"] != theauth.OAuthErrInvalidGrant {
			t.Errorf("error=%v, want invalid_grant", body["error"])
		}
	})

	t.Run("refresh_token_happy_path", func(t *testing.T) {
		fx := newTokenDispatchFixture(t)
		// First exchange the code for an initial token pair so we have a
		// rotatable refresh token.
		seed := url.Values{}
		seed.Set("grant_type", theauth.GrantTypeAuthorizationCode)
		seed.Set("client_id", fx.client.ClientID)
		seed.Set("client_secret", fx.client.ClientSecret)
		seed.Set("code", fx.code)
		seed.Set("code_verifier", fx.verifier)
		seed.Set("redirect_uri", "https://app.example.com/cb")
		_, initial := postForm(t, fx.server, seed, nil)
		refresh, _ := initial["refresh_token"].(string)
		if refresh == "" {
			t.Fatalf("seed missing refresh_token: %v", initial)
		}
		form := url.Values{}
		form.Set("grant_type", theauth.GrantTypeRefreshToken)
		form.Set("client_id", fx.client.ClientID)
		form.Set("client_secret", fx.client.ClientSecret)
		form.Set("refresh_token", refresh)
		resp, body := postForm(t, fx.server, form, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status=%d body=%v", resp.StatusCode, body)
		}
		if next, _ := body["refresh_token"].(string); next == "" || next == refresh {
			t.Fatalf("refresh_token did not rotate: %v", body)
		}
	})

	t.Run("refresh_token_unknown", func(t *testing.T) {
		fx := newTokenDispatchFixture(t)
		form := url.Values{}
		form.Set("grant_type", theauth.GrantTypeRefreshToken)
		form.Set("client_id", fx.client.ClientID)
		form.Set("client_secret", fx.client.ClientSecret)
		form.Set("refresh_token", "not-a-real-refresh-token")
		resp, body := postForm(t, fx.server, form, nil)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status=%d body=%v", resp.StatusCode, body)
		}
		if body["error"] != theauth.OAuthErrInvalidGrant {
			t.Errorf("error=%v, want invalid_grant", body["error"])
		}
	})

	t.Run("refresh_token_missing", func(t *testing.T) {
		fx := newTokenDispatchFixture(t)
		form := url.Values{}
		form.Set("grant_type", theauth.GrantTypeRefreshToken)
		form.Set("client_id", fx.client.ClientID)
		form.Set("client_secret", fx.client.ClientSecret)
		resp, body := postForm(t, fx.server, form, nil)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status=%d body=%v", resp.StatusCode, body)
		}
		if body["error"] != theauth.OAuthErrInvalidRequest {
			t.Errorf("error=%v, want invalid_request", body["error"])
		}
	})

	t.Run("client_credentials_happy_path", func(t *testing.T) {
		a, srv, _, _ := newAgentASHarness(t)
		_ = a
		agentClient := newAgentAndClient(t, srv, a)
		form := url.Values{}
		form.Set("grant_type", theauth.GrantTypeClientCredentials)
		form.Set("client_id", agentClient.ClientID)
		form.Set("client_secret", agentClient.Secret)
		form.Set("resource", "https://files.example.com/mcp")
		form.Set("scope", "files.read")
		resp, body := postForm(t, srv, form, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status=%d body=%v", resp.StatusCode, body)
		}
		if got, _ := body["access_token"].(string); got == "" {
			t.Fatalf("missing access_token: %v", body)
		}
		if body["token_type"] != "Bearer" {
			t.Errorf("token_type=%v, want Bearer", body["token_type"])
		}
	})

	t.Run("client_credentials_missing_resource", func(t *testing.T) {
		a, srv, _, _ := newAgentASHarness(t)
		_ = a
		agentClient := newAgentAndClient(t, srv, a)
		form := url.Values{}
		form.Set("grant_type", theauth.GrantTypeClientCredentials)
		form.Set("client_id", agentClient.ClientID)
		form.Set("client_secret", agentClient.Secret)
		form.Set("scope", "files.read")
		resp, body := postForm(t, srv, form, nil)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status=%d body=%v", resp.StatusCode, body)
		}
		if body["error"] != theauth.OAuthErrInvalidTarget {
			t.Errorf("error=%v, want invalid_target", body["error"])
		}
	})

	t.Run("token_exchange_happy_path", func(t *testing.T) {
		a, srv, user, _ := newAgentASHarness(t)
		agentClient := newAgentAndClient(t, srv, a)
		// Grant a delegation so the exchange has a backing row.
		grantDelegation(t, a, user.ID, agentClient.AgentID)
		// Mint a user-rooted access token through the AS code flow first.
		userClient := registerTestClient(t, srv)
		userTok := authorizationCodeToken(t, srv, a, user, userClient)
		form := url.Values{}
		form.Set("grant_type", theauth.GrantTypeTokenExchange)
		form.Set("client_id", agentClient.ClientID)
		form.Set("client_secret", agentClient.Secret)
		form.Set("subject_token", userTok)
		form.Set("subject_token_type", theauth.TokenTypeAccessToken)
		form.Set("resource", "https://files.example.com/mcp")
		form.Set("scope", "files.read")
		resp, body := postForm(t, srv, form, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status=%d body=%v", resp.StatusCode, body)
		}
		if got, _ := body["issued_token_type"].(string); got != theauth.TokenTypeAccessToken {
			t.Errorf("issued_token_type=%v, want access_token URI", got)
		}
	})

	t.Run("token_exchange_missing_subject_token", func(t *testing.T) {
		a, srv, _, _ := newAgentASHarness(t)
		agentClient := newAgentAndClient(t, srv, a)
		form := url.Values{}
		form.Set("grant_type", theauth.GrantTypeTokenExchange)
		form.Set("client_id", agentClient.ClientID)
		form.Set("client_secret", agentClient.Secret)
		form.Set("resource", "https://files.example.com/mcp")
		resp, body := postForm(t, srv, form, nil)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status=%d body=%v", resp.StatusCode, body)
		}
		if body["error"] != theauth.OAuthErrInvalidRequest {
			t.Errorf("error=%v, want invalid_request", body["error"])
		}
	})

	t.Run("token_exchange_invalid_subject_token", func(t *testing.T) {
		a, srv, _, _ := newAgentASHarness(t)
		agentClient := newAgentAndClient(t, srv, a)
		form := url.Values{}
		form.Set("grant_type", theauth.GrantTypeTokenExchange)
		form.Set("client_id", agentClient.ClientID)
		form.Set("client_secret", agentClient.Secret)
		form.Set("subject_token", "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.")
		form.Set("subject_token_type", theauth.TokenTypeAccessToken)
		form.Set("resource", "https://files.example.com/mcp")
		resp, body := postForm(t, srv, form, nil)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status=%d body=%v", resp.StatusCode, body)
		}
		if body["error"] != theauth.OAuthErrInvalidRequest {
			t.Errorf("error=%v, want invalid_request, body=%v", body["error"], body)
		}
	})

	t.Run("unsupported_grant_type", func(t *testing.T) {
		fx := newTokenDispatchFixture(t)
		form := url.Values{}
		form.Set("grant_type", "password")
		form.Set("client_id", fx.client.ClientID)
		form.Set("client_secret", fx.client.ClientSecret)
		form.Set("username", "alice")
		form.Set("password", "hunter2")
		resp, body := postForm(t, fx.server, form, nil)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status=%d body=%v", resp.StatusCode, body)
		}
		if body["error"] != theauth.OAuthErrUnsupportedGrantType {
			t.Errorf("error=%v, want unsupported_grant_type", body["error"])
		}
	})

	t.Run("missing_grant_type", func(t *testing.T) {
		fx := newTokenDispatchFixture(t)
		form := url.Values{}
		form.Set("client_id", fx.client.ClientID)
		form.Set("client_secret", fx.client.ClientSecret)
		resp, body := postForm(t, fx.server, form, nil)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status=%d body=%v", resp.StatusCode, body)
		}
		if body["error"] != theauth.OAuthErrUnsupportedGrantType {
			t.Errorf("error=%v, want unsupported_grant_type", body["error"])
		}
	})

	t.Run("malformed_form_body", func(t *testing.T) {
		fx := newTokenDispatchFixture(t)
		// %ZZ is an invalid percent-encoding triplet; net/url's ParseForm
		// surfaces this as an error before the handler ever inspects fields.
		req, _ := http.NewRequest(http.MethodPost, fx.server.URL+"/oauth/token", strings.NewReader("grant_type=%ZZ"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		raw, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status=%d body=%s", resp.StatusCode, raw)
		}
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		if body["error"] != theauth.OAuthErrInvalidRequest {
			t.Errorf("error=%v, want invalid_request", body["error"])
		}
	})

	t.Run("invalid_client_via_basic_auth", func(t *testing.T) {
		fx := newTokenDispatchFixture(t)
		form := url.Values{}
		form.Set("grant_type", theauth.GrantTypeAuthorizationCode)
		form.Set("code", fx.code)
		form.Set("code_verifier", fx.verifier)
		form.Set("redirect_uri", "https://app.example.com/cb")
		resp, body := postForm(t, fx.server, form, func(r *http.Request) {
			r.SetBasicAuth(fx.client.ClientID, "wrong-secret")
		})
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status=%d body=%v", resp.StatusCode, body)
		}
		if body["error"] != theauth.OAuthErrInvalidClient {
			t.Errorf("error=%v, want invalid_client", body["error"])
		}
	})

	t.Run("invalid_client_unknown_id", func(t *testing.T) {
		fx := newTokenDispatchFixture(t)
		form := url.Values{}
		form.Set("grant_type", theauth.GrantTypeAuthorizationCode)
		form.Set("client_id", "ghost-client-id")
		form.Set("client_secret", "x")
		form.Set("code", fx.code)
		form.Set("code_verifier", fx.verifier)
		form.Set("redirect_uri", "https://app.example.com/cb")
		resp, body := postForm(t, fx.server, form, nil)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status=%d body=%v", resp.StatusCode, body)
		}
		if body["error"] != theauth.OAuthErrInvalidClient {
			t.Errorf("error=%v, want invalid_client", body["error"])
		}
	})

	t.Run("invalid_client_missing_credentials", func(t *testing.T) {
		fx := newTokenDispatchFixture(t)
		form := url.Values{}
		form.Set("grant_type", theauth.GrantTypeAuthorizationCode)
		form.Set("code", fx.code)
		form.Set("code_verifier", fx.verifier)
		form.Set("redirect_uri", "https://app.example.com/cb")
		resp, body := postForm(t, fx.server, form, nil)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status=%d body=%v", resp.StatusCode, body)
		}
		if body["error"] != theauth.OAuthErrInvalidClient {
			t.Errorf("error=%v, want invalid_client", body["error"])
		}
	})

	t.Run("authorization_code_missing_code", func(t *testing.T) {
		fx := newTokenDispatchFixture(t)
		form := url.Values{}
		form.Set("grant_type", theauth.GrantTypeAuthorizationCode)
		form.Set("client_id", fx.client.ClientID)
		form.Set("client_secret", fx.client.ClientSecret)
		form.Set("code_verifier", fx.verifier)
		form.Set("redirect_uri", "https://app.example.com/cb")
		resp, body := postForm(t, fx.server, form, nil)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status=%d body=%v", resp.StatusCode, body)
		}
		if body["error"] != theauth.OAuthErrInvalidRequest {
			t.Errorf("error=%v, want invalid_request", body["error"])
		}
	})
}

// newAgentASHarness mirrors newASHarness but configures AgentIdentity so the
// fixture supports client_credentials + token-exchange. Used by the token
// dispatch tests for the v2.0 phase 3+4 grant cases.
func newAgentASHarness(t *testing.T) (*theauth.TheAuth, *httptest.Server, theauth.User, string) {
	t.Helper()
	a, store := newAgentASInstance(t)
	user := theauth.User{ID: ulid.New(), Email: "u@example.com"}
	if _, err := store.CreateUser(context.Background(), user); err != nil {
		t.Fatal(err)
	}
	rawToken, err := crypto.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	hash := crypto.HashToken(rawToken)
	sess := theauth.Session{
		ID:        ulid.New(),
		UserID:    user.ID,
		TokenHash: hash,
		AuthLevel: theauth.AuthLevelFull,
	}
	if _, err := store.CreateSession(context.Background(), sess); err != nil {
		t.Fatal(err)
	}
	r := chi.NewRouter()
	a.Mount(r)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return a, srv, user, rawToken
}

// agentClientHandle bundles the registered OAuth client for an agent plus
// the underlying agent ID, used by token-dispatch tests that need to drive
// client_credentials or token-exchange against a freshly minted agent.
type agentClientHandle struct {
	ClientID string
	Secret   string
	AgentID  theauth.ULID
}

func newAgentAndClient(t *testing.T, _ *httptest.Server, a *theauth.TheAuth) agentClientHandle {
	t.Helper()
	ctx := context.Background()
	owner := theauth.User{ID: ulid.New(), Email: "owner@example.com"}
	// store comes from newAgentASInstance via the AS harness; we cannot
	// reach back into it here, so we make a fresh agent owned by a user that
	// the AS only sees through the agent path. CreateAgent does not require
	// the user to exist in storage; it only writes the owner ULID.
	_ = owner
	uid := ulid.New()
	ag, secret, err := a.CreateAgent(ctx, theauth.CreateAgentInput{
		Owner: theauth.AgentOwner{UserID: &uid},
		Name:  "harness-agent",
		Scope: []string{"files.read", "files.write"},
	})
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	return agentClientHandle{ClientID: secret.ClientID, Secret: secret.Secret, AgentID: ag.ID}
}

// grantDelegation grants files.read+files.write to the named agent on behalf
// of the named user, sized to cover the token-exchange happy path.
func grantDelegation(t *testing.T, a *theauth.TheAuth, userID, agentID theauth.ULID) {
	t.Helper()
	if _, err := a.GrantDelegation(context.Background(), theauth.GrantDelegationInput{
		UserID:             userID,
		AgentID:            agentID,
		Scope:              []string{"files.read", "files.write"},
		Resource:           "https://files.example.com/mcp",
		MaxDurationSeconds: 3600,
	}); err != nil {
		t.Fatalf("GrantDelegation: %v", err)
	}
}

// authorizationCodeToken mints a user access token via StartAuthorize +
// ExchangeAuthorizationCode, returning the access token. The returned token
// is bound to "https://files.example.com/mcp" with scope files.read.
func authorizationCodeToken(t *testing.T, _ *httptest.Server, a *theauth.TheAuth, user theauth.User, client theauth.RegisteredClient) string {
	t.Helper()
	verifier, _ := crypto.NewCodeVerifier()
	ctx := context.Background()
	res, err := a.StartAuthorize(ctx, theauth.AuthorizeRequest{
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

// TestHandleIntrospectAndRevokeHTTP exercises /oauth/introspect and
// /oauth/revoke through httptest. Asserts the cache-control max-age on
// introspection matches IntrospectionCacheTTL.
func TestHandleIntrospectAndRevokeHTTP(t *testing.T) {
	t.Run("introspect_active_with_cache_control", func(t *testing.T) {
		fx := newTokenDispatchFixture(t)
		// Seed an access token via the code flow.
		seed := url.Values{}
		seed.Set("grant_type", theauth.GrantTypeAuthorizationCode)
		seed.Set("client_id", fx.client.ClientID)
		seed.Set("client_secret", fx.client.ClientSecret)
		seed.Set("code", fx.code)
		seed.Set("code_verifier", fx.verifier)
		seed.Set("redirect_uri", "https://app.example.com/cb")
		_, body := postForm(t, fx.server, seed, nil)
		access, _ := body["access_token"].(string)
		if access == "" {
			t.Fatalf("seed missing access_token: %v", body)
		}

		form := url.Values{}
		form.Set("token", access)
		form.Set("resource", "https://files.example.com/mcp")
		req, _ := http.NewRequest(http.MethodPost, fx.server.URL+"/oauth/introspect", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(fx.client.ClientID, fx.client.ClientSecret)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		raw, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status=%d body=%s", resp.StatusCode, raw)
		}
		cc := resp.Header.Get("Cache-Control")
		if !strings.Contains(cc, "private") || !strings.Contains(cc, "max-age=") {
			t.Errorf("Cache-Control=%q, want private + max-age", cc)
		}
		var doc map[string]any
		_ = json.Unmarshal(raw, &doc)
		if doc["active"] != true {
			t.Errorf("active=%v, want true; body=%s", doc["active"], raw)
		}
	})

	t.Run("introspect_invalid_client", func(t *testing.T) {
		fx := newTokenDispatchFixture(t)
		form := url.Values{}
		form.Set("token", "anything")
		req, _ := http.NewRequest(http.MethodPost, fx.server.URL+"/oauth/introspect", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(fx.client.ClientID, "wrong-secret")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status=%d", resp.StatusCode)
		}
	})

	t.Run("introspect_malformed_form", func(t *testing.T) {
		fx := newTokenDispatchFixture(t)
		req, _ := http.NewRequest(http.MethodPost, fx.server.URL+"/oauth/introspect", strings.NewReader("%ZZ"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status=%d", resp.StatusCode)
		}
	})

	t.Run("revoke_unknown_token_returns_200", func(t *testing.T) {
		fx := newTokenDispatchFixture(t)
		form := url.Values{}
		form.Set("token", "phantom-token")
		form.Set("token_type_hint", "refresh_token")
		req, _ := http.NewRequest(http.MethodPost, fx.server.URL+"/oauth/revoke", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(fx.client.ClientID, fx.client.ClientSecret)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status=%d", resp.StatusCode)
		}
	})

	t.Run("revoke_invalid_client", func(t *testing.T) {
		fx := newTokenDispatchFixture(t)
		form := url.Values{}
		form.Set("token", "anything")
		req, _ := http.NewRequest(http.MethodPost, fx.server.URL+"/oauth/revoke", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(fx.client.ClientID, "wrong-secret")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status=%d", resp.StatusCode)
		}
	})

	t.Run("revoke_malformed_form", func(t *testing.T) {
		fx := newTokenDispatchFixture(t)
		req, _ := http.NewRequest(http.MethodPost, fx.server.URL+"/oauth/revoke", strings.NewReader("%ZZ"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status=%d", resp.StatusCode)
		}
	})
}
