package as_test

// rar_test.go: RFC 9396 authorization_details through authorize, token,
// refresh and introspection.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/crypto"
	internalas "github.com/glincker/theauth-go/v2/internal/as"
	"github.com/go-chi/chi/v5"
)

const payment = `[{"type":"payment","actions":["initiate","status"],"locations":["https://bank.example.com"]}]`

func withRAR(types ...string) func(*theauth.AuthorizationServerConfig) {
	return func(c *theauth.AuthorizationServerConfig) { c.RAR = &theauth.RARConfig{Types: types} }
}

func withDetails(raw string) func(*theauth.AuthorizeRequest) {
	return func(r *theauth.AuthorizeRequest) { r.AuthorizationDetails = raw }
}

func jwtClaim(t *testing.T, token, name string) any {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(strings.Split(token, ".")[1])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m[name]
}

func TestRARFlowCarriesDetails(t *testing.T) {
	a, store := newASInstance(t, withRAR("payment", "account"))
	ctx := context.Background()
	client := confidentialClient(t, a)
	tok, _ := codeFlow(t, a, store, client, withDetails(payment))

	if len(tok.AuthorizationDetails) == 0 {
		t.Fatal("token response must echo authorization_details")
	}
	claim, ok := jwtClaim(t, tok.AccessToken, "authorization_details").([]any)
	if !ok || len(claim) != 1 || claim[0].(map[string]any)["type"] != "payment" {
		t.Fatalf("access token claim: %v", claim)
	}

	resp, _, err := a.IntrospectToken(ctx, tok.AccessToken, client.ClientID, client.ClientSecret, policyResource)
	if err != nil || !resp.Active {
		t.Fatalf("introspect: %v %v", resp.Active, err)
	}
	var got []map[string]any
	if err := json.Unmarshal(resp.AuthorizationDetails, &got); err != nil || len(got) != 1 || got[0]["type"] != "payment" {
		t.Fatalf("introspection details: %s (%v)", resp.AuthorizationDetails, err)
	}
}

func TestRARNoDetailsNoClaim(t *testing.T) {
	a, store := newASInstance(t, withRAR("payment"))
	tok, _ := codeFlow(t, a, store, confidentialClient(t, a), nil)
	if len(tok.AuthorizationDetails) != 0 || jwtClaim(t, tok.AccessToken, "authorization_details") != nil {
		t.Fatal("a request without details must not produce the claim")
	}
}

func TestRARRefreshNarrowing(t *testing.T) {
	a, store := newASInstance(t, withRAR("payment", "account"))
	ctx := context.Background()
	client := confidentialClient(t, a)
	tok, _ := codeFlow(t, a, store, client, withDetails(payment))

	refresh := func(refreshToken, details string) (theauth.TokenResponse, error) {
		return a.RefreshAccessToken(ctx, theauth.TokenRequest{
			GrantType: theauth.GrantTypeRefreshToken, ClientID: client.ClientID, ClientSecret: client.ClientSecret,
			RefreshToken: refreshToken, AuthorizationDetails: details,
		})
	}

	t.Run("broader request refused", func(t *testing.T) {
		_, err := refresh(tok.RefreshToken, `[{"type":"payment","actions":["initiate","cancel"]}]`)
		if !errors.Is(err, theauth.ErrOAuthInvalidAuthorizationDetails) {
			t.Fatalf("want invalid_authorization_details, got %v", err)
		}
	})
	t.Run("other type refused", func(t *testing.T) {
		_, err := refresh(tok.RefreshToken, `[{"type":"account"}]`)
		if !errors.Is(err, theauth.ErrOAuthInvalidAuthorizationDetails) {
			t.Fatalf("want invalid_authorization_details, got %v", err)
		}
	})
	t.Run("subset narrows", func(t *testing.T) {
		next, err := refresh(tok.RefreshToken, `[{"type":"payment","actions":["status"]}]`)
		if err != nil {
			t.Fatalf("refresh: %v", err)
		}
		var got []map[string]any
		if err := json.Unmarshal(next.AuthorizationDetails, &got); err != nil {
			t.Fatal(err)
		}
		actions, _ := got[0]["actions"].([]any)
		if len(actions) != 1 || actions[0] != "status" {
			t.Fatalf("narrowed actions: %v", actions)
		}
		// The narrowed grant is what the next refresh token carries.
		_, err = refresh(next.RefreshToken, payment)
		if !errors.Is(err, theauth.ErrOAuthInvalidAuthorizationDetails) {
			t.Fatalf("narrowing must not be reversible, got %v", err)
		}
	})
	t.Run("omitted keeps the grant", func(t *testing.T) {
		fresh, _ := codeFlow(t, a, store, client, withDetails(payment))
		next, err := refresh(fresh.RefreshToken, "")
		if err != nil {
			t.Fatal(err)
		}
		if len(next.AuthorizationDetails) == 0 {
			t.Fatal("refresh without the parameter must keep the granted details")
		}
	})
}

func TestRARAuthorizeRejections(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name string
		mut  func(*theauth.AuthorizationServerConfig)
		raw  string
	}{
		{"rar disabled", func(*theauth.AuthorizationServerConfig) {}, payment},
		{"unsupported type", withRAR("account"), payment},
		{"not an array", withRAR("payment"), `{"type":"payment"}`},
		{"empty array", withRAR("payment"), `[]`},
		{"missing type", withRAR("payment"), `[{"actions":["x"]}]`},
		{"bad member type", withRAR("payment"), `[{"type":"payment","actions":"initiate"}]`},
		{"trailing data", withRAR("payment"), payment + `{}`},
		{"not json", withRAR("payment"), `payment`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, store := newASInstance(t, tc.mut)
			client := confidentialClient(t, a)
			user := theauth.User{ID: newUserID(t, store)}
			_, err := a.StartAuthorize(ctx, authorizeReq(client, tc.raw), &user)
			if !errors.Is(err, theauth.ErrOAuthInvalidAuthorizationDetails) {
				t.Fatalf("want invalid_authorization_details, got %v", err)
			}
		})
	}
}

func TestRARTooManyDetails(t *testing.T) {
	a, store := newASInstance(t, func(c *theauth.AuthorizationServerConfig) {
		c.RAR = &theauth.RARConfig{Types: []string{"payment"}, MaxDetails: 2}
	})
	client := confidentialClient(t, a)
	user := theauth.User{ID: newUserID(t, store)}
	three := `[{"type":"payment"},{"type":"payment"},{"type":"payment"}]`
	if _, err := a.StartAuthorize(context.Background(), authorizeReq(client, three), &user); !errors.Is(err, theauth.ErrOAuthInvalidAuthorizationDetails) {
		t.Fatalf("want invalid_authorization_details, got %v", err)
	}
}

func TestRARClientTypeRestriction(t *testing.T) {
	a, store := newASInstance(t, withRAR("payment", "account"))
	client := registerPolicyClient(t, a, func(r *theauth.ClientRegistrationRequest) {
		r.AuthorizationDetailsTypes = []string{"account"}
	})
	user := theauth.User{ID: newUserID(t, store)}
	_, err := a.StartAuthorize(context.Background(), authorizeReq(client, payment), &user)
	if !errors.Is(err, theauth.ErrOAuthInvalidAuthorizationDetails) {
		t.Fatalf("client limited to account must not get payment, got %v", err)
	}
	if _, err := a.StartAuthorize(context.Background(), authorizeReq(client, `[{"type":"account"}]`), &user); err != nil {
		t.Fatalf("allowed type refused: %v", err)
	}
}

func TestRARRegistrationValidatesTypes(t *testing.T) {
	a, _ := newASInstance(t, withRAR("payment"))
	_, err := a.RegisterClient(context.Background(), theauth.ClientRegistrationRequest{
		RedirectURIs: []string{"https://app.example.com/cb"}, TokenEndpointAuthMethod: theauth.ClientAuthSecretBasic,
		AuthorizationDetailsTypes: []string{"unknown"},
	}, false)
	if err == nil {
		t.Fatal("an unsupported type must fail registration")
	}
}

func TestRARMetadataAdvertisesTypes(t *testing.T) {
	a, _ := newASInstance(t, withRAR("payment", "account"))
	meta, err := a.ASMetadataDoc()
	if err != nil {
		t.Fatal(err)
	}
	if len(meta.AuthorizationDetailsTypesSupported) != 2 {
		t.Fatalf("metadata: %v", meta.AuthorizationDetailsTypesSupported)
	}
	b, _ := newASInstance(t)
	meta, _ = b.ASMetadataDoc()
	if meta.AuthorizationDetailsTypesSupported != nil {
		t.Fatal("RAR off must not advertise types")
	}
}

func TestRAROpaqueTokenIntrospection(t *testing.T) {
	a, store := newASInstance(t, withRAR("payment"), withTokenPolicy(&theauth.TokenPolicyConfig{}))
	client := registerPolicyClient(t, a, func(r *theauth.ClientRegistrationRequest) {
		r.AccessTokenFormat = theauth.AccessTokenFormatOpaque
	})
	tok, _ := codeFlow(t, a, store, client, withDetails(payment))
	resp, _, err := a.IntrospectToken(context.Background(), tok.AccessToken, client.ClientID, client.ClientSecret, policyResource)
	if err != nil || !resp.Active || len(resp.AuthorizationDetails) == 0 {
		t.Fatalf("opaque introspection lost the details: %+v %v", resp, err)
	}
}

func TestRARHTTPSurface(t *testing.T) {
	a, _ := newASInstance(t, withRAR("payment"), withTokenPolicy(&theauth.TokenPolicyConfig{SigningAlgs: []string{"ES256"}}),
		func(c *theauth.AuthorizationServerConfig) { c.RegistrationTokens = []string{"initial-access-token"} })
	r := chi.NewRouter()
	a.Mount(r)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	// Registration accepts and echoes the new client metadata.
	body := `{"redirect_uris":["https://app.example.com/cb"],"access_token_signed_response_alg":"ES256","authorization_details_types":["payment"]}`
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/oauth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer initial-access-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var reg map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&reg); err != nil || resp.StatusCode != http.StatusCreated {
		t.Fatalf("register: status %d err %v body %v", resp.StatusCode, err, reg)
	}
	if reg["access_token_signed_response_alg"] != "ES256" || reg["authorization_details_types"] == nil {
		t.Fatalf("metadata not echoed: %v", reg)
	}
	clientID, _ := reg["client_id"].(string)

	// A malformed value is redirected back as invalid_authorization_details.
	verifier, _ := crypto.NewCodeVerifier()
	q := url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {"https://app.example.com/cb"},
		"scope": {"files.read"}, "resource": {policyResource},
		"code_challenge": {crypto.CodeChallenge(verifier)}, "code_challenge_method": {"S256"},
		"authorization_details": {`[{"type":"nope"}]`},
	}
	resp2, err := noRedirect.Get(srv.URL + "/oauth/authorize?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp2.Body.Close() }()
	if loc := resp2.Header.Get("Location"); resp2.StatusCode != http.StatusFound || !strings.Contains(loc, "error=invalid_authorization_details") {
		t.Fatalf("authorize: status %d location %q", resp2.StatusCode, loc)
	}

	// Grants that cannot honour the parameter refuse it.
	form := url.Values{"grant_type": {"client_credentials"}, "authorization_details": {payment}}
	resp3, err := http.PostForm(srv.URL+"/oauth/token", form)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp3.Body.Close() }()
	var e map[string]any
	_ = json.NewDecoder(resp3.Body).Decode(&e)
	if resp3.StatusCode != http.StatusBadRequest || e["error"] != "invalid_authorization_details" {
		t.Fatalf("token: status %d body %v", resp3.StatusCode, e)
	}

	// Metadata advertises the types.
	resp4, err := http.Get(srv.URL + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp4.Body.Close() }()
	var doc map[string]any
	_ = json.NewDecoder(resp4.Body).Decode(&doc)
	if doc["authorization_details_types_supported"] == nil {
		t.Fatalf("metadata: %v", doc)
	}
}

// exchangeRARCode redeems code against the par/jar harness resource and
// returns the token response.
func exchangeRARCode(t *testing.T, a *theauth.TheAuth, client theauth.RegisteredClient, code, verifier string) theauth.TokenResponse {
	t.Helper()
	tok, err := a.ExchangeAuthorizationCode(context.Background(), theauth.TokenRequest{
		GrantType: theauth.GrantTypeAuthorizationCode, ClientID: client.ClientID, ClientSecret: client.ClientSecret,
		Code: code, CodeVerifier: verifier, RedirectURI: "https://app.example.com/cb",
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	return tok
}

func TestRARThroughPAR(t *testing.T) {
	a, srv, _, session := newPARASHarness(t, withRAR("payment"))
	client := registerClientWithBody(t, srv, baseClientBody())
	verifier, _ := crypto.NewCodeVerifier()
	form := url.Values{
		"response_type": {"code"}, "client_id": {client.ClientID}, "redirect_uri": {"https://app.example.com/cb"},
		"scope": {"read"}, "code_challenge": {crypto.CodeChallenge(verifier)}, "code_challenge_method": {"S256"},
		"resource": {"https://api.example.com"}, "authorization_details": {payment},
	}
	body, status := postPAR(t, srv, client.ClientID, client.ClientSecret, form)
	if status != http.StatusCreated {
		t.Fatalf("PAR: %d %v", status, body)
	}
	code, status := authorizeWithRequestURI(t, srv, session, client.ClientID, body["request_uri"].(string))
	if status != http.StatusFound || code == "" {
		t.Fatalf("authorize: %d", status)
	}
	tok := exchangeRARCode(t, a, client, code, verifier)
	if len(tok.AuthorizationDetails) == 0 {
		t.Fatal("details pushed through PAR were lost")
	}
}

func TestRARThroughJAR(t *testing.T) {
	a, srv, _, session := newJARASHarness(t, withRAR("payment"))
	privKey, pubJWKS, err := internalas.GenerateECKeyJWK()
	if err != nil {
		t.Fatal(err)
	}
	client := registerClientWithBody(t, srv, clientBodyWithJWKS(pubJWKS))
	verifier, _ := crypto.NewCodeVerifier()
	inner := internalas.AuthorizeRequest{
		ClientID: client.ClientID, RedirectURI: "https://app.example.com/cb", ResponseType: "code",
		Scope: []string{"read"}, CodeChallenge: crypto.CodeChallenge(verifier), CodeChallengeMethod: "S256",
		Resource: "https://api.example.com", AuthorizationDetails: payment,
	}
	rawJWT, err := internalas.BuildJARJWT(privKey, client.ClientID, "https://auth.example.com", inner, time.Now().Add(5*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	code, status := authorizeWithRequestObject(t, srv, session, client.ClientID, rawJWT)
	if status != http.StatusFound || code == "" {
		t.Fatalf("authorize: %d", status)
	}
	tok := exchangeRARCode(t, a, client, code, verifier)
	if len(tok.AuthorizationDetails) == 0 {
		t.Fatal("details carried in a request object were lost")
	}
}
