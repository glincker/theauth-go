package as_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/crypto"
	"github.com/glincker/theauth-go/v2/internal/ulid"
	"github.com/glincker/theauth-go/v2/storage/memory"
	"github.com/go-chi/chi/v5"
)

// sessionAuthHarness serves the AS over HTTP with one session carrying the
// given authentication record, and returns a function that runs authorize
// plus the code exchange and yields the access token claims.
func sessionAuthHarness(t *testing.T, sess theauth.Session, mutate func(*theauth.AuthorizationServerConfig)) func(extra url.Values) (map[string]any, *http.Response) {
	t.Helper()
	store := memory.New()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	asCfg := &theauth.AuthorizationServerConfig{
		Issuer:             "https://auth.example.com",
		Resources:          []theauth.ProtectedResource{{Identifier: authCtxResource, Scopes: []string{"files.read"}}},
		DisableRotation:    true,
		RegistrationTokens: []string{"initial-access-token"},
	}
	if mutate != nil {
		mutate(asCfg)
	}
	a, err := theauth.New(theauth.Config{
		Storage: store, BaseURL: "https://auth.example.com", EncryptionKey: key, AuthorizationServer: asCfg,
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
	sess.ID, sess.UserID, sess.TokenHash = ulid.New(), user.ID, crypto.HashToken(raw)
	sess.AuthLevel = theauth.AuthLevelFull
	if sess.CreatedAt.IsZero() {
		sess.CreatedAt = time.Now().Add(-time.Minute)
	}
	sess.ExpiresAt = time.Now().Add(time.Hour)
	if _, err := store.CreateSession(context.Background(), sess); err != nil {
		t.Fatal(err)
	}
	r := chi.NewRouter()
	a.Mount(r)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	client := registerTestClient(t, srv)

	return func(extra url.Values) (map[string]any, *http.Response) {
		verifier, _ := crypto.NewCodeVerifier()
		q := url.Values{
			"response_type": {"code"}, "client_id": {client.ClientID},
			"redirect_uri": {"https://app.example.com/cb"}, "scope": {"files.read"},
			"resource": {authCtxResource}, "code_challenge": {crypto.CodeChallenge(verifier)},
			"code_challenge_method": {"S256"},
		}
		for k, v := range extra {
			q[k] = v
		}
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/oauth/authorize?"+q.Encode(), nil)
		req.AddCookie(&http.Cookie{Name: "theauth_session", Value: raw})
		resp, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		loc, _ := url.Parse(resp.Header.Get("Location"))
		if loc == nil || loc.Query().Get("code") == "" {
			return nil, resp
		}
		tok, err := a.ExchangeAuthorizationCode(context.Background(), theauth.TokenRequest{
			GrantType: theauth.GrantTypeAuthorizationCode, ClientID: client.ClientID, ClientSecret: client.ClientSecret,
			Code: loc.Query().Get("code"), CodeVerifier: verifier, RedirectURI: "https://app.example.com/cb",
		})
		if err != nil {
			t.Fatalf("exchange: %v", err)
		}
		return decodeJWTPayload(t, tok.AccessToken), resp
	}
}

func amrOf(claims map[string]any) []string {
	raw, _ := claims["amr"].([]any)
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		s, _ := v.(string)
		out = append(out, s)
	}
	return out
}

func TestSessionRecordDrivesAMRACRAndAuthTime(t *testing.T) {
	authAt := time.Now().Add(-30 * time.Second).Truncate(time.Second)
	run := sessionAuthHarness(t, theauth.Session{
		AuthMethods: []string{"pwd", "otp", "mfa"}, AuthTime: authAt,
		CreatedAt: time.Now().Add(-time.Hour),
	}, nil)
	claims, _ := run(nil)
	if claims == nil {
		t.Fatal("authorize did not issue a code")
	}
	if got := amrOf(claims); !reflect.DeepEqual(got, []string{"pwd", "otp", "mfa"}) {
		t.Errorf("amr = %v, want [pwd otp mfa]", got)
	}
	if claims["acr"] != "urn:theauth:acr:mfa" {
		t.Errorf("acr = %v, want mfa", claims["acr"])
	}
	if got, _ := claims["auth_time"].(float64); int64(got) != authAt.Unix() {
		t.Errorf("auth_time = %v, want session AuthTime %d (not CreatedAt)", claims["auth_time"], authAt.Unix())
	}
}

func TestSessionRecordPasskeyAndSSO(t *testing.T) {
	for _, tc := range []struct {
		method string
		acr    string
	}{
		{"hwk", "urn:example:gold"},
		{"sso", "urn:theauth:acr:1fa"},
	} {
		run := sessionAuthHarness(t, theauth.Session{AuthMethods: []string{tc.method}, AuthTime: time.Now()},
			func(c *theauth.AuthorizationServerConfig) { c.ACRValues = map[string]string{"hwk": "urn:example:gold"} })
		claims, _ := run(nil)
		if claims == nil || !reflect.DeepEqual(amrOf(claims), []string{tc.method}) || claims["acr"] != tc.acr {
			t.Errorf("%s: amr %v acr %v, want [%s] %s", tc.method, claims["amr"], claims["acr"], tc.method, tc.acr)
		}
	}
}

func TestLegacySessionKeepsPasswordDefault(t *testing.T) {
	created := time.Now().Add(-2 * time.Minute).Truncate(time.Second)
	run := sessionAuthHarness(t, theauth.Session{CreatedAt: created}, nil)
	claims, _ := run(nil)
	if claims == nil {
		t.Fatal("authorize did not issue a code")
	}
	if got := amrOf(claims); !reflect.DeepEqual(got, []string{"pwd"}) {
		t.Errorf("legacy amr = %v, want [pwd]", got)
	}
	if claims["acr"] != "urn:theauth:acr:1fa" {
		t.Errorf("legacy acr = %v, want 1fa", claims["acr"])
	}
	if got, _ := claims["auth_time"].(float64); int64(got) != created.Unix() {
		t.Errorf("legacy auth_time = %v, want CreatedAt %d", claims["auth_time"], created.Unix())
	}
	// A legacy session cannot satisfy an mfa acr_values request.
	if c, resp := run(url.Values{"acr_values": {"urn:theauth:acr:mfa"}}); c != nil || resp.StatusCode != http.StatusFound {
		t.Errorf("legacy session satisfied mfa acr_values: claims %v status %d", c, resp.StatusCode)
	}
}

func TestRecordedMFASessionSatisfiesACRValues(t *testing.T) {
	run := sessionAuthHarness(t, theauth.Session{AuthMethods: []string{"pwd", "otp", "mfa"}, AuthTime: time.Now()}, nil)
	if claims, _ := run(url.Values{"acr_values": {"urn:theauth:acr:mfa"}}); claims == nil {
		t.Fatal("recorded mfa session did not satisfy acr_values mfa")
	}
}

func TestSessionAMRHookOverridesRecord(t *testing.T) {
	run := sessionAuthHarness(t, theauth.Session{AuthMethods: []string{"pwd"}, AuthTime: time.Now()},
		func(c *theauth.AuthorizationServerConfig) {
			c.SessionAMR = func(_ context.Context, s *theauth.Session) []string {
				if s.HasMethod("pwd") {
					return []string{"hwk"}
				}
				return nil
			}
		})
	claims, _ := run(nil)
	if claims == nil || !reflect.DeepEqual(amrOf(claims), []string{"hwk"}) {
		t.Errorf("amr = %v, want hook result [hwk]", claims["amr"])
	}
}
