package as_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/crypto"
	internalas "github.com/glincker/theauth-go/v2/internal/as"
	"github.com/glincker/theauth-go/v2/internal/ulid"
	"github.com/glincker/theauth-go/v2/storage/memory"
	"github.com/go-chi/chi/v5"
)

const authCtxResource = "https://files.example.com/mcp"

// authCodeFlow runs authorize + code exchange with ac attached and returns
// the token response, the client and the authorize error (when any).
func authCodeFlow(t *testing.T, a *theauth.TheAuth, store *memory.Store, ac *internalas.AuthContext, mut func(*theauth.AuthorizeRequest)) (theauth.TokenResponse, theauth.RegisteredClient, error) {
	t.Helper()
	ctx := context.Background()
	if ac != nil {
		ctx = internalas.WithAuthContext(ctx, *ac)
	}
	user := theauth.User{ID: ulid.New(), Email: "alice@example.com"}
	if _, err := store.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	client := confidentialClient(t, a)
	verifier, _ := crypto.NewCodeVerifier()
	req := theauth.AuthorizeRequest{
		ClientID:            client.ClientID,
		RedirectURI:         "https://app.example.com/cb",
		ResponseType:        "code",
		Scope:               []string{"files.read"},
		CodeChallenge:       crypto.CodeChallenge(verifier),
		CodeChallengeMethod: "S256",
		Resource:            authCtxResource,
	}
	if mut != nil {
		mut(&req)
	}
	res, err := a.StartAuthorize(ctx, req, &user)
	if err != nil {
		return theauth.TokenResponse{}, client, err
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
		t.Fatalf("exchange: %v", err)
	}
	return tok, client, nil
}

func TestAuthContextClaimsAndACRMapping(t *testing.T) {
	authAt := time.Now().Add(-90 * time.Second).Truncate(time.Second)
	tests := []struct {
		name    string
		acr     map[string]string
		amr     []string
		wantACR string
	}{
		{"single factor default", nil, []string{"pwd"}, "urn:theauth:acr:1fa"},
		{"two methods default", nil, []string{"pwd", "otp"}, "urn:theauth:acr:mfa"},
		{"mfa method default", nil, []string{"mfa"}, "urn:theauth:acr:mfa"},
		{"configured exact set, key order irrelevant", map[string]string{"pwd+otp": "urn:example:silver", "hwk": "urn:example:gold"}, []string{"otp", "pwd"}, "urn:example:silver"},
		{"configured single", map[string]string{"hwk": "urn:example:gold"}, []string{"hwk"}, "urn:example:gold"},
		{"unmapped set falls back to default", map[string]string{"hwk": "urn:example:gold"}, []string{"pwd"}, "urn:theauth:acr:1fa"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a, store := newASInstance(t, func(c *theauth.AuthorizationServerConfig) { c.ACRValues = tc.acr })
			ac := &internalas.AuthContext{AuthTime: authAt, AMR: tc.amr}
			tok, client, err := authCodeFlow(t, a, store, ac, nil)
			if err != nil {
				t.Fatalf("authorize: %v", err)
			}
			claims := decodeJWTPayload(t, tok.AccessToken)
			if got, _ := claims["auth_time"].(float64); int64(got) != authAt.Unix() {
				t.Errorf("auth_time = %v, want %d", claims["auth_time"], authAt.Unix())
			}
			if claims["acr"] != tc.wantACR {
				t.Errorf("acr = %v, want %q", claims["acr"], tc.wantACR)
			}
			gotAMR, _ := claims["amr"].([]any)
			if len(gotAMR) != len(tc.amr) {
				t.Errorf("amr = %v, want %v", claims["amr"], tc.amr)
			}
			resp, _, err := a.IntrospectToken(context.Background(), tok.AccessToken, client.ClientID, client.ClientSecret, authCtxResource)
			if err != nil || !resp.Active {
				t.Fatalf("introspect: %+v %v", resp, err)
			}
			if resp.AuthTime != authAt.Unix() || resp.ACR != tc.wantACR || !reflect.DeepEqual(resp.AMR, tc.amr) {
				t.Errorf("introspection auth context = %d %q %v", resp.AuthTime, resp.ACR, resp.AMR)
			}
		})
	}
}

func TestAuthContextAbsentEmitsNoClaims(t *testing.T) {
	a, store := newASInstance(t)
	tok, _, err := authCodeFlow(t, a, store, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	claims := decodeJWTPayload(t, tok.AccessToken)
	for _, k := range []string{"auth_time", "acr", "amr"} {
		if _, ok := claims[k]; ok {
			t.Errorf("claim %q present without an auth context", k)
		}
	}
}

func TestRefreshCarriesAuthContextForward(t *testing.T) {
	a, store := newASInstance(t)
	authAt := time.Now().Add(-20 * time.Minute).Truncate(time.Second)
	ac := &internalas.AuthContext{AuthTime: authAt, AMR: []string{"pwd", "otp"}}
	tok, client, err := authCodeFlow(t, a, store, ac, nil)
	if err != nil {
		t.Fatal(err)
	}
	refresh := tok.RefreshToken
	for i := 0; i < 2; i++ {
		rt, err := a.RefreshAccessToken(context.Background(), theauth.TokenRequest{
			GrantType:    theauth.GrantTypeRefreshToken,
			ClientID:     client.ClientID,
			ClientSecret: client.ClientSecret,
			RefreshToken: refresh,
		})
		if err != nil {
			t.Fatalf("refresh %d: %v", i, err)
		}
		claims := decodeJWTPayload(t, rt.AccessToken)
		if got, _ := claims["auth_time"].(float64); int64(got) != authAt.Unix() {
			t.Errorf("refresh %d auth_time = %v, want original %d", i, claims["auth_time"], authAt.Unix())
		}
		if claims["acr"] != "urn:theauth:acr:mfa" {
			t.Errorf("refresh %d acr = %v", i, claims["acr"])
		}
		if amr, _ := claims["amr"].([]any); len(amr) != 2 {
			t.Errorf("refresh %d amr = %v", i, claims["amr"])
		}
		refresh = rt.RefreshToken
	}
}

func TestAuthorizeMaxAgeAndACRValues(t *testing.T) {
	maxAge := func(n int64) *int64 { return &n }
	now := time.Now()
	tests := []struct {
		name   string
		ac     *internalas.AuthContext
		mut    func(*theauth.AuthorizeRequest)
		reauth bool
	}{
		{"fresh session within max_age", &internalas.AuthContext{AuthTime: now.Add(-30 * time.Second), AMR: []string{"pwd"}},
			func(r *theauth.AuthorizeRequest) { r.MaxAge = maxAge(300) }, false},
		{"session older than max_age", &internalas.AuthContext{AuthTime: now.Add(-10 * time.Minute), AMR: []string{"pwd"}},
			func(r *theauth.AuthorizeRequest) { r.MaxAge = maxAge(300) }, true},
		{"max_age zero always reauthenticates", &internalas.AuthContext{AuthTime: now, AMR: []string{"pwd"}},
			func(r *theauth.AuthorizeRequest) { r.MaxAge = maxAge(0) }, true},
		{"unknown auth time fails max_age", &internalas.AuthContext{AMR: []string{"pwd"}},
			func(r *theauth.AuthorizeRequest) { r.MaxAge = maxAge(300) }, true},
		{"no context fails max_age", nil,
			func(r *theauth.AuthorizeRequest) { r.MaxAge = maxAge(300) }, true},
		{"acr satisfied", &internalas.AuthContext{AuthTime: now, AMR: []string{"pwd", "otp"}},
			func(r *theauth.AuthorizeRequest) { r.ACRValues = []string{"urn:other", "urn:theauth:acr:mfa"} }, false},
		{"acr not satisfied", &internalas.AuthContext{AuthTime: now, AMR: []string{"pwd"}},
			func(r *theauth.AuthorizeRequest) { r.ACRValues = []string{"urn:theauth:acr:mfa"} }, true},
		{"max_age and acr both required", &internalas.AuthContext{AuthTime: now.Add(-time.Hour), AMR: []string{"pwd", "otp"}},
			func(r *theauth.AuthorizeRequest) {
				r.MaxAge = maxAge(60)
				r.ACRValues = []string{"urn:theauth:acr:mfa"}
			}, true},
		{"no constraints, no context", nil, nil, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a, store := newASInstance(t)
			_, _, err := authCodeFlow(t, a, store, tc.ac, tc.mut)
			switch {
			case tc.reauth && !theauth.IsReauthRequired(err):
				t.Fatalf("err = %v, want reauth required", err)
			case !tc.reauth && err != nil:
				t.Fatalf("err = %v, want success", err)
			}
			if tc.reauth && theauth.IsLoginRequired(err) {
				t.Error("reauth must be distinguishable from missing session")
			}
		})
	}
}

func TestACRValuesSupportedMetadata(t *testing.T) {
	a, _ := newASInstance(t)
	meta, err := a.ASMetadataDoc()
	if err != nil {
		t.Fatal(err)
	}
	if len(meta.ACRValuesSupported) != 0 {
		t.Errorf("unconfigured must not advertise acr_values_supported, got %v", meta.ACRValuesSupported)
	}
	a, _ = newASInstance(t, func(c *theauth.AuthorizationServerConfig) {
		c.ACRValues = map[string]string{"pwd": "urn:b", "pwd+otp": "urn:a", "hwk": "urn:a"}
	})
	meta, _ = a.ASMetadataDoc()
	if !reflect.DeepEqual(meta.ACRValuesSupported, []string{"urn:a", "urn:b"}) {
		t.Errorf("acr_values_supported = %v", meta.ACRValuesSupported)
	}
}

// authzHTTPHarness serves the AS with one session created at sessAge ago.
func authzHTTPHarness(t *testing.T, sessAge time.Duration) (*httptest.Server, theauth.RegisteredClient, string) {
	t.Helper()
	store := memory.New()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	a, err := theauth.New(theauth.Config{
		Storage: store, BaseURL: "https://auth.example.com", EncryptionKey: key,
		AuthorizationServer: &theauth.AuthorizationServerConfig{
			Issuer:             "https://auth.example.com",
			Resources:          []theauth.ProtectedResource{{Identifier: authCtxResource, Scopes: []string{"files.read"}}},
			DisableRotation:    true,
			RegistrationTokens: []string{"initial-access-token"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	user := theauth.User{ID: ulid.New(), Email: "alice@example.com"}
	if _, err := store.CreateUser(context.Background(), user); err != nil {
		t.Fatal(err)
	}
	raw, _ := crypto.NewToken()
	if _, err := store.CreateSession(context.Background(), theauth.Session{
		ID: ulid.New(), UserID: user.ID, TokenHash: crypto.HashToken(raw), AuthLevel: theauth.AuthLevelFull,
		CreatedAt: time.Now().Add(-sessAge), ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	r := chi.NewRouter()
	a.Mount(r)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return srv, registerTestClient(t, srv), raw
}

func TestAuthorizeHandlerMaxAgeRedirects(t *testing.T) {
	srv, client, sess := authzHTTPHarness(t, 10*time.Minute)
	verifier, _ := crypto.NewCodeVerifier()
	get := func(extra url.Values) *http.Response {
		q := url.Values{
			"response_type":         {"code"},
			"client_id":             {client.ClientID},
			"redirect_uri":          {"https://app.example.com/cb"},
			"scope":                 {"files.read"},
			"state":                 {"s1"},
			"resource":              {authCtxResource},
			"code_challenge":        {crypto.CodeChallenge(verifier)},
			"code_challenge_method": {"S256"},
		}
		for k, v := range extra {
			q[k] = v
		}
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/oauth/authorize?"+q.Encode(), nil)
		req.AddCookie(&http.Cookie{Name: "theauth_session", Value: sess})
		resp, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp
	}

	t.Run("within max_age issues a code", func(t *testing.T) {
		resp := get(url.Values{"max_age": {"3600"}})
		loc, _ := url.Parse(resp.Header.Get("Location"))
		if resp.StatusCode != http.StatusFound || loc.Query().Get("code") == "" {
			t.Fatalf("status %d Location %q", resp.StatusCode, resp.Header.Get("Location"))
		}
	})
	t.Run("older than max_age redirects to login with hints", func(t *testing.T) {
		resp := get(url.Values{"max_age": {"60"}})
		loc, _ := url.Parse(resp.Header.Get("Location"))
		if resp.StatusCode != http.StatusFound || !strings.HasSuffix(loc.Path, "/login") {
			t.Fatalf("status %d Location %q", resp.StatusCode, resp.Header.Get("Location"))
		}
		if loc.Query().Get("reauth") != "1" || loc.Query().Get("max_age") != "60" || !strings.Contains(loc.Query().Get("next"), "max_age=60") {
			t.Errorf("login query = %v", loc.Query())
		}
	})
	t.Run("unmet acr_values redirects to login", func(t *testing.T) {
		resp := get(url.Values{"acr_values": {"urn:theauth:acr:mfa"}})
		loc, _ := url.Parse(resp.Header.Get("Location"))
		if !strings.HasSuffix(loc.Path, "/login") || loc.Query().Get("acr_values") != "urn:theauth:acr:mfa" {
			t.Fatalf("Location %q", resp.Header.Get("Location"))
		}
	})
	t.Run("prompt none answers login_required to the client", func(t *testing.T) {
		resp := get(url.Values{"max_age": {"60"}, "prompt": {"none"}})
		loc, _ := url.Parse(resp.Header.Get("Location"))
		if loc.Host != "app.example.com" || loc.Query().Get("error") != "login_required" || loc.Query().Get("state") != "s1" {
			t.Fatalf("Location %q", resp.Header.Get("Location"))
		}
	})
	t.Run("invalid max_age is invalid_request", func(t *testing.T) {
		if resp := get(url.Values{"max_age": {"soon"}}); resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status %d", resp.StatusCode)
		}
	})
}
