package as_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/crypto"
	internalas "github.com/glincker/theauth-go/internal/as"
	"github.com/glincker/theauth-go/internal/ulid"
	"github.com/glincker/theauth-go/storage/memory"
	"github.com/go-chi/chi/v5"
)

// ---------- shared harness ----------

// newPARASHarness returns an AS+server wired with PAR enabled. The caller
// may pass mutators to adjust the AuthorizationServerConfig.
func newPARASHarness(t *testing.T, mut ...func(*theauth.AuthorizationServerConfig)) (*theauth.TheAuth, *httptest.Server, theauth.User, string) {
	t.Helper()
	asCfg := &theauth.AuthorizationServerConfig{
		Issuer:             "https://auth.example.com",
		Resources:          []theauth.ProtectedResource{{Identifier: "https://api.example.com", Scopes: []string{"read", "write"}}},
		DisableRotation:    true,
		RegistrationTokens: []string{"initial-access-token"},
		PAR:                &theauth.PARConfig{RequestURITTL: 10 * time.Second},
	}
	for _, m := range mut {
		m(asCfg)
	}
	return buildASHarness(t, asCfg)
}

func newJARASHarness(t *testing.T, mut ...func(*theauth.AuthorizationServerConfig)) (*theauth.TheAuth, *httptest.Server, theauth.User, string) {
	t.Helper()
	asCfg := &theauth.AuthorizationServerConfig{
		Issuer:             "https://auth.example.com",
		Resources:          []theauth.ProtectedResource{{Identifier: "https://api.example.com", Scopes: []string{"read", "write"}}},
		DisableRotation:    true,
		RegistrationTokens: []string{"initial-access-token"},
		JAR:                &theauth.JARConfig{AcceptedAlgorithms: []string{"ES256", "RS256", "EdDSA"}},
	}
	for _, m := range mut {
		m(asCfg)
	}
	return buildASHarness(t, asCfg)
}

func newPARJARASHarness(t *testing.T) (*theauth.TheAuth, *httptest.Server, theauth.User, string) {
	t.Helper()
	asCfg := &theauth.AuthorizationServerConfig{
		Issuer:             "https://auth.example.com",
		Resources:          []theauth.ProtectedResource{{Identifier: "https://api.example.com", Scopes: []string{"read", "write"}}},
		DisableRotation:    true,
		RegistrationTokens: []string{"initial-access-token"},
		PAR:                &theauth.PARConfig{RequestURITTL: 10 * time.Second},
		JAR:                &theauth.JARConfig{AcceptedAlgorithms: []string{"ES256", "RS256", "EdDSA"}},
	}
	return buildASHarness(t, asCfg)
}

func buildASHarness(t *testing.T, asCfg *theauth.AuthorizationServerConfig) (*theauth.TheAuth, *httptest.Server, theauth.User, string) {
	t.Helper()
	store := memory.New()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1) // deterministic; fine for tests
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
		t.Fatalf("CreateUser: %v", err)
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
		ExpiresAt: time.Now().Add(24 * time.Hour),
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

// postPAR POSTs the given form to /oauth/par using HTTP Basic auth.
func postPAR(t *testing.T, srv *httptest.Server, clientID, clientSecret string, form url.Values) (map[string]any, int) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/oauth/par", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, clientSecret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /oauth/par: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	return body, resp.StatusCode
}

// authorizeWithRequestURI sends GET /oauth/authorize?client_id=...&request_uri=...
// with a valid session cookie. Returns (code, statusCode).
func authorizeWithRequestURI(t *testing.T, srv *httptest.Server, sessionToken, clientID, requestURI string) (string, int) {
	t.Helper()
	u := fmt.Sprintf("%s/oauth/authorize?client_id=%s&request_uri=%s",
		srv.URL, url.QueryEscape(clientID), url.QueryEscape(requestURI))
	return doAuthorize(t, srv, u, sessionToken)
}

// authorizeWithRequestObject sends GET /oauth/authorize?client_id=...&request=<JWT>.
func authorizeWithRequestObject(t *testing.T, srv *httptest.Server, sessionToken, clientID, rawJWT string) (string, int) {
	t.Helper()
	u := fmt.Sprintf("%s/oauth/authorize?client_id=%s&request=%s",
		srv.URL, url.QueryEscape(clientID), url.QueryEscape(rawJWT))
	return doAuthorize(t, srv, u, sessionToken)
}

func doAuthorize(t *testing.T, _ *httptest.Server, authorizeURL, sessionToken string) (string, int) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, authorizeURL, nil)
	req.AddCookie(&http.Cookie{Name: "theauth_session", Value: sessionToken})
	noRedirect := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := noRedirect.Do(req)
	if err != nil {
		t.Fatalf("GET /oauth/authorize: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		return "", resp.StatusCode
	}
	loc := resp.Header.Get("Location")
	parsed, _ := url.Parse(loc)
	return parsed.Query().Get("code"), http.StatusFound
}

// registerClientWithBody registers a DCR client and returns the registered client.
func registerClientWithBody(t *testing.T, srv *httptest.Server, body string) theauth.RegisteredClient {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/oauth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer initial-access-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register client: status %d", resp.StatusCode)
	}
	var reg theauth.RegisteredClient
	_ = json.NewDecoder(resp.Body).Decode(&reg)
	return reg
}

func baseClientBody() string {
	return `{"redirect_uris":["https://app.example.com/cb"]}`
}

func clientBodyWithJWKS(pubJWKS []byte) string {
	return fmt.Sprintf(`{"redirect_uris":["https://app.example.com/cb"],"jwks":%s}`, string(pubJWKS))
}

// ---------- TestPARHappyPath ----------

func TestPARHappyPath(t *testing.T) {
	_, srv, _, rawToken := newPARASHarness(t)
	client := registerClientWithBody(t, srv, baseClientBody())

	verifier, _ := crypto.NewCodeVerifier()
	form := url.Values{
		"response_type":         {"code"},
		"client_id":             {client.ClientID},
		"redirect_uri":          {"https://app.example.com/cb"},
		"scope":                 {"read"},
		"state":                 {"csrf-abc"},
		"code_challenge":        {crypto.CodeChallenge(verifier)},
		"code_challenge_method": {"S256"},
		"resource":              {"https://api.example.com"},
	}
	body, status := postPAR(t, srv, client.ClientID, client.ClientSecret, form)
	if status != http.StatusCreated {
		t.Fatalf("PAR: expected 201, got %d body=%v", status, body)
	}
	requestURI, _ := body["request_uri"].(string)
	if !strings.HasPrefix(requestURI, "urn:ietf:params:oauth:request_uri:") {
		t.Fatalf("request_uri has wrong prefix: %q", requestURI)
	}
	if ei, _ := body["expires_in"].(float64); ei <= 0 {
		t.Fatalf("expires_in missing or zero: %v", body)
	}

	code, status := authorizeWithRequestURI(t, srv, rawToken, client.ClientID, requestURI)
	if status != http.StatusFound {
		t.Fatalf("authorize: expected 302, got %d", status)
	}
	if code == "" {
		t.Fatal("no code in redirect")
	}
}

// ---------- TestPARRequestURIOneShot ----------

func TestPARRequestURIOneShot(t *testing.T) {
	_, srv, _, rawToken := newPARASHarness(t)
	client := registerClientWithBody(t, srv, baseClientBody())

	verifier, _ := crypto.NewCodeVerifier()
	form := url.Values{
		"response_type": {"code"}, "client_id": {client.ClientID},
		"redirect_uri": {"https://app.example.com/cb"}, "scope": {"read"},
		"code_challenge": {crypto.CodeChallenge(verifier)}, "code_challenge_method": {"S256"},
		"resource": {"https://api.example.com"},
	}
	body, _ := postPAR(t, srv, client.ClientID, client.ClientSecret, form)
	requestURI, _ := body["request_uri"].(string)

	// First use: success.
	_, status1 := authorizeWithRequestURI(t, srv, rawToken, client.ClientID, requestURI)
	if status1 != http.StatusFound {
		t.Fatalf("first use: expected 302, got %d", status1)
	}

	// Second use: must fail.
	_, status2 := authorizeWithRequestURI(t, srv, rawToken, client.ClientID, requestURI)
	if status2 == http.StatusFound {
		t.Fatal("second use of consumed request_uri must not succeed")
	}
}

// ---------- TestPARRequestURIExpired ----------

func TestPARRequestURIExpired(t *testing.T) {
	_, srv, _, rawToken := newPARASHarness(t, func(c *theauth.AuthorizationServerConfig) {
		c.PAR = &theauth.PARConfig{RequestURITTL: 1 * time.Millisecond}
	})
	client := registerClientWithBody(t, srv, baseClientBody())

	verifier, _ := crypto.NewCodeVerifier()
	form := url.Values{
		"response_type": {"code"}, "client_id": {client.ClientID},
		"redirect_uri": {"https://app.example.com/cb"}, "scope": {"read"},
		"code_challenge": {crypto.CodeChallenge(verifier)}, "code_challenge_method": {"S256"},
		"resource": {"https://api.example.com"},
	}
	body, status := postPAR(t, srv, client.ClientID, client.ClientSecret, form)
	if status != http.StatusCreated {
		t.Fatalf("PAR: expected 201, got %d", status)
	}
	requestURI, _ := body["request_uri"].(string)

	// Allow TTL to elapse.
	time.Sleep(10 * time.Millisecond)

	_, authStatus := authorizeWithRequestURI(t, srv, rawToken, client.ClientID, requestURI)
	if authStatus == http.StatusFound {
		t.Fatal("expired request_uri must not result in 302")
	}
}

// ---------- TestPARRejectsInlineParamsWhenBothPresent ----------

func TestPARRejectsInlineParamsWhenBothPresent(t *testing.T) {
	_, srv, _, rawToken := newPARASHarness(t)
	client := registerClientWithBody(t, srv, baseClientBody())

	verifier, _ := crypto.NewCodeVerifier()
	form := url.Values{
		"response_type": {"code"}, "client_id": {client.ClientID},
		"redirect_uri": {"https://app.example.com/cb"}, "scope": {"read"},
		"code_challenge": {crypto.CodeChallenge(verifier)}, "code_challenge_method": {"S256"},
		"resource": {"https://api.example.com"},
	}
	body, _ := postPAR(t, srv, client.ClientID, client.ClientSecret, form)
	requestURI, _ := body["request_uri"].(string)

	// Include request_uri AND an inline param (response_type=code).
	u := fmt.Sprintf("%s/oauth/authorize?client_id=%s&request_uri=%s&response_type=code",
		srv.URL, url.QueryEscape(client.ClientID), url.QueryEscape(requestURI))
	req, _ := http.NewRequest(http.MethodGet, u, nil)
	req.AddCookie(&http.Cookie{Name: "theauth_session", Value: rawToken})
	noRedir := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	resp, _ := noRedir.Do(req)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for mixed request_uri+inline, got %d", resp.StatusCode)
	}
}

// ---------- TestPARRequirePAR ----------

func TestPARRequirePAR(t *testing.T) {
	_, srv, _, rawToken := newPARASHarness(t, func(c *theauth.AuthorizationServerConfig) {
		c.PAR = &theauth.PARConfig{RequirePAR: true, RequestURITTL: 10 * time.Second}
	})
	client := registerClientWithBody(t, srv, baseClientBody())

	verifier, _ := crypto.NewCodeVerifier()
	// Plain inline /authorize: must be rejected when RequirePAR=true.
	u := fmt.Sprintf("%s/oauth/authorize?client_id=%s&response_type=code&redirect_uri=%s&scope=read&code_challenge=%s&code_challenge_method=S256&resource=%s",
		srv.URL,
		url.QueryEscape(client.ClientID),
		url.QueryEscape("https://app.example.com/cb"),
		url.QueryEscape(crypto.CodeChallenge(verifier)),
		url.QueryEscape("https://api.example.com"),
	)
	req, _ := http.NewRequest(http.MethodGet, u, nil)
	req.AddCookie(&http.Cookie{Name: "theauth_session", Value: rawToken})
	noRedir := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	resp, _ := noRedir.Do(req)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("RequirePAR: expected 400, got %d", resp.StatusCode)
	}
}

// ---------- TestJARHappyPath ----------

func TestJARHappyPath(t *testing.T) {
	_, srv, _, rawToken := newJARASHarness(t)
	privKey, pubJWKS, err := internalas.GenerateECKeyJWK()
	if err != nil {
		t.Fatalf("GenerateECKeyJWK: %v", err)
	}
	client := registerClientWithBody(t, srv, clientBodyWithJWKS(pubJWKS))

	verifier, _ := crypto.NewCodeVerifier()
	innerReq := internalas.AuthorizeRequest{
		ClientID:            client.ClientID,
		RedirectURI:         "https://app.example.com/cb",
		ResponseType:        "code",
		Scope:               []string{"read"},
		State:               "jar-state",
		CodeChallenge:       crypto.CodeChallenge(verifier),
		CodeChallengeMethod: "S256",
		Resource:            "https://api.example.com",
	}
	rawJWT, err := internalas.BuildJARJWT(privKey, client.ClientID, "https://auth.example.com", innerReq, time.Now().Add(5*time.Minute))
	if err != nil {
		t.Fatalf("BuildJARJWT: %v", err)
	}

	code, status := authorizeWithRequestObject(t, srv, rawToken, client.ClientID, rawJWT)
	if status != http.StatusFound {
		t.Fatalf("JAR happy path: expected 302, got %d", status)
	}
	if code == "" {
		t.Fatal("JAR: no code in redirect")
	}
}

// ---------- TestJARSignatureFailure ----------

func TestJARSignatureFailure(t *testing.T) {
	_, srv, _, rawToken := newJARASHarness(t)
	privKey, pubJWKS, _ := internalas.GenerateECKeyJWK()
	client := registerClientWithBody(t, srv, clientBodyWithJWKS(pubJWKS))

	verifier, _ := crypto.NewCodeVerifier()
	innerReq := internalas.AuthorizeRequest{
		ClientID:            client.ClientID,
		RedirectURI:         "https://app.example.com/cb",
		ResponseType:        "code",
		Scope:               []string{"read"},
		CodeChallenge:       crypto.CodeChallenge(verifier),
		CodeChallengeMethod: "S256",
		Resource:            "https://api.example.com",
	}
	rawJWT, _ := internalas.BuildJARJWT(privKey, client.ClientID, "https://auth.example.com", innerReq, time.Now().Add(5*time.Minute))

	// Tamper: flip last byte of the signature segment.
	parts := strings.Split(rawJWT, ".")
	sig := []byte(parts[2])
	sig[len(sig)-1] ^= 0x01
	tamperedJWT := parts[0] + "." + parts[1] + "." + string(sig)

	_, status := authorizeWithRequestObject(t, srv, rawToken, client.ClientID, tamperedJWT)
	if status != http.StatusBadRequest {
		t.Fatalf("tampered JAR: expected 400, got %d", status)
	}
}

// ---------- TestJAROuterParamsIgnored ----------

func TestJAROuterParamsIgnored(t *testing.T) {
	_, srv, _, rawToken := newJARASHarness(t)
	privKey, pubJWKS, _ := internalas.GenerateECKeyJWK()
	client := registerClientWithBody(t, srv, clientBodyWithJWKS(pubJWKS))

	verifier, _ := crypto.NewCodeVerifier()
	// Inner JWT has scope=read.
	innerReq := internalas.AuthorizeRequest{
		ClientID:            client.ClientID,
		RedirectURI:         "https://app.example.com/cb",
		ResponseType:        "code",
		Scope:               []string{"read"},
		CodeChallenge:       crypto.CodeChallenge(verifier),
		CodeChallengeMethod: "S256",
		Resource:            "https://api.example.com",
	}
	rawJWT, _ := internalas.BuildJARJWT(privKey, client.ClientID, "https://auth.example.com", innerReq, time.Now().Add(5*time.Minute))

	// Outer URL says scope=write -- must be ignored. The inner scope=read
	// is valid so the request must succeed.
	u := fmt.Sprintf("%s/oauth/authorize?client_id=%s&scope=write&request=%s",
		srv.URL,
		url.QueryEscape(client.ClientID),
		url.QueryEscape(rawJWT),
	)
	req, _ := http.NewRequest(http.MethodGet, u, nil)
	req.AddCookie(&http.Cookie{Name: "theauth_session", Value: rawToken})
	noRedir := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	resp, _ := noRedir.Do(req)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("JAR outer params ignored: expected 302, got %d", resp.StatusCode)
	}
}

// ---------- TestJARRejectedAlgorithm ----------

func TestJARRejectedAlgorithm(t *testing.T) {
	_, srv, _, rawToken := newJARASHarness(t)
	privKey, pubJWKS, _ := internalas.GenerateECKeyJWK()
	client := registerClientWithBody(t, srv, clientBodyWithJWKS(pubJWKS))

	verifier, _ := crypto.NewCodeVerifier()
	innerReq := internalas.AuthorizeRequest{
		ClientID:            client.ClientID,
		RedirectURI:         "https://app.example.com/cb",
		ResponseType:        "code",
		Scope:               []string{"read"},
		CodeChallenge:       crypto.CodeChallenge(verifier),
		CodeChallengeMethod: "S256",
		Resource:            "https://api.example.com",
	}
	validJWT, _ := internalas.BuildJARJWT(privKey, client.ClientID, "https://auth.example.com", innerReq, time.Now().Add(5*time.Minute))
	parts := strings.Split(validJWT, ".")

	// Swap the header to declare HS256 (always forbidden).
	hs256Header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"oauth-authz-req+jwt"}`))
	hs256JWT := hs256Header + "." + parts[1] + "." + parts[2]

	_, status := authorizeWithRequestObject(t, srv, rawToken, client.ClientID, hs256JWT)
	if status != http.StatusBadRequest {
		t.Fatalf("HS256 JAR: expected 400, got %d", status)
	}
}

// ---------- TestJARExpiredJWT ----------

func TestJARExpiredJWT(t *testing.T) {
	_, srv, _, rawToken := newJARASHarness(t)
	privKey, pubJWKS, _ := internalas.GenerateECKeyJWK()
	client := registerClientWithBody(t, srv, clientBodyWithJWKS(pubJWKS))

	verifier, _ := crypto.NewCodeVerifier()
	innerReq := internalas.AuthorizeRequest{
		ClientID:            client.ClientID,
		RedirectURI:         "https://app.example.com/cb",
		ResponseType:        "code",
		Scope:               []string{"read"},
		CodeChallenge:       crypto.CodeChallenge(verifier),
		CodeChallengeMethod: "S256",
		Resource:            "https://api.example.com",
	}
	// exp in the past.
	rawJWT, _ := internalas.BuildJARJWT(privKey, client.ClientID, "https://auth.example.com", innerReq, time.Now().Add(-1*time.Minute))

	_, status := authorizeWithRequestObject(t, srv, rawToken, client.ClientID, rawJWT)
	if status != http.StatusBadRequest {
		t.Fatalf("expired JAR: expected 400, got %d", status)
	}
}

// ---------- TestPARAndJARTogether (FAPI 2.0 happy path) ----------

func TestPARAndJARTogether(t *testing.T) {
	_, srv, _, rawToken := newPARJARASHarness(t)
	privKey, pubJWKS, _ := internalas.GenerateECKeyJWK()
	client := registerClientWithBody(t, srv, clientBodyWithJWKS(pubJWKS))

	verifier, _ := crypto.NewCodeVerifier()
	innerReq := internalas.AuthorizeRequest{
		ClientID:            client.ClientID,
		RedirectURI:         "https://app.example.com/cb",
		ResponseType:        "code",
		Scope:               []string{"read"},
		State:               "fapi-state",
		CodeChallenge:       crypto.CodeChallenge(verifier),
		CodeChallengeMethod: "S256",
		Resource:            "https://api.example.com",
	}
	rawJWT, err := internalas.BuildJARJWT(privKey, client.ClientID, "https://auth.example.com", innerReq, time.Now().Add(5*time.Minute))
	if err != nil {
		t.Fatalf("BuildJARJWT: %v", err)
	}

	// POST the JAR JWT to /oauth/par.
	form := url.Values{"request": {rawJWT}, "client_id": {client.ClientID}}
	parBody, parStatus := postPAR(t, srv, client.ClientID, client.ClientSecret, form)
	if parStatus != http.StatusCreated {
		t.Fatalf("PAR+JAR: expected 201, got %d body=%v", parStatus, parBody)
	}
	requestURI, _ := parBody["request_uri"].(string)
	if !strings.HasPrefix(requestURI, "urn:ietf:params:oauth:request_uri:") {
		t.Fatalf("unexpected request_uri: %q", requestURI)
	}

	// GET /oauth/authorize?client_id=...&request_uri=...
	code, status := authorizeWithRequestURI(t, srv, rawToken, client.ClientID, requestURI)
	if status != http.StatusFound {
		t.Fatalf("FAPI 2.0 authorize: expected 302, got %d", status)
	}
	if code == "" {
		t.Fatal("FAPI 2.0 authorize: no code in redirect")
	}
}

// ---------- AS Metadata advertises PAR/JAR fields ----------

func TestASMetadataAdvertisesPAR(t *testing.T) {
	_, srv, _, _ := newPARASHarness(t)
	resp, err := http.Get(srv.URL + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var doc map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&doc)
	if ep, _ := doc["pushed_authorization_request_endpoint"].(string); !strings.HasSuffix(ep, "/oauth/par") {
		t.Errorf("metadata missing pushed_authorization_request_endpoint, got %v", ep)
	}
}

func TestASMetadataAdvertisesJAR(t *testing.T) {
	_, srv, _, _ := newJARASHarness(t)
	resp, err := http.Get(srv.URL + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var doc map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&doc)
	if supported, _ := doc["request_parameter_supported"].(bool); !supported {
		t.Errorf("metadata missing request_parameter_supported=true")
	}
	algs, _ := doc["request_object_signing_alg_values_supported"].([]any)
	if len(algs) == 0 {
		t.Errorf("metadata missing request_object_signing_alg_values_supported")
	}
}
