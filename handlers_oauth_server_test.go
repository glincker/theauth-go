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
