package microsoft_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/provider/internal/oauthtest"
	msprov "github.com/glincker/theauth-go/provider/microsoft"
)

func TestNameIsMicrosoft(t *testing.T) {
	p := msprov.New(msprov.Config{ClientID: "x", ClientSecret: "y"})
	if got := p.Name(); got != "microsoft" {
		t.Fatalf("Name() = %q, want %q", got, "microsoft")
	}
}

func TestAuthURLDefaultsTenantToCommon(t *testing.T) {
	p := msprov.New(msprov.Config{ClientID: "x", ClientSecret: "y"})
	got := p.AuthURL("s", "c", "https://r", nil)
	if !strings.Contains(got, "/common/oauth2/v2.0/authorize") {
		t.Fatalf("AuthURL = %q, want path containing /common/oauth2/v2.0/authorize", got)
	}
}

func TestAuthURLUsesConfiguredTenant(t *testing.T) {
	p := msprov.New(msprov.Config{
		ClientID:     "x",
		ClientSecret: "y",
		Tenant:       "00000000-0000-0000-0000-000000000001",
	})
	got := p.AuthURL("s", "c", "https://r", nil)
	if !strings.Contains(got, "/00000000-0000-0000-0000-000000000001/oauth2/v2.0/authorize") {
		t.Fatalf("AuthURL = %q, want tenant GUID in path", got)
	}
}

func TestAuthURLUsesConfiguredTenantDomain(t *testing.T) {
	p := msprov.New(msprov.Config{
		ClientID:     "x",
		ClientSecret: "y",
		Tenant:       "contoso.onmicrosoft.com",
	})
	got := p.AuthURL("s", "c", "https://r", nil)
	if !strings.Contains(got, "/contoso.onmicrosoft.com/oauth2/v2.0/authorize") {
		t.Fatalf("AuthURL = %q, want tenant domain in path", got)
	}
}

func TestAuthURLOverrideBypassesTenantSubstitution(t *testing.T) {
	p := msprov.New(msprov.Config{
		ClientID:     "x",
		ClientSecret: "y",
		Tenant:       "ignored",
		AuthorizeURL: "https://example/x",
	})
	got := p.AuthURL("s", "c", "https://r", nil)
	if !strings.HasPrefix(got, "https://example/x?") {
		t.Fatalf("AuthURL = %q, want override URL verbatim", got)
	}
}

func TestAuthURLContainsRequiredParams(t *testing.T) {
	p := msprov.New(msprov.Config{ClientID: "client-abc", ClientSecret: "shh"})
	got := p.AuthURL("state-xyz", "challenge-123", "https://app.example.com/auth/providers/microsoft/callback", []string{"openid", "email", "profile"})
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("AuthURL not parseable: %v", err)
	}
	q := u.Query()
	wantParams := map[string]string{
		"client_id":             "client-abc",
		"redirect_uri":          "https://app.example.com/auth/providers/microsoft/callback",
		"response_type":         "code",
		"scope":                 "openid email profile",
		"state":                 "state-xyz",
		"code_challenge":        "challenge-123",
		"code_challenge_method": "S256",
	}
	for k, want := range wantParams {
		if got := q.Get(k); got != want {
			t.Fatalf("AuthURL param %q = %q, want %q", k, got, want)
		}
	}
}

func TestAuthURLDefaultsScopes(t *testing.T) {
	p := msprov.New(msprov.Config{ClientID: "x", ClientSecret: "y"})
	u, _ := url.Parse(p.AuthURL("s", "c", "https://r", nil))
	if got := u.Query().Get("scope"); got != "openid email profile" {
		t.Fatalf("default scope = %q, want %q", got, "openid email profile")
	}
}

func TestExchangeCodeParsesTokenResponse(t *testing.T) {
	mux, srv := oauthtest.NewMux(t)
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		oauthtest.AssertTokenForm(t, r, oauthtest.TokenExpect{
			ClientID:     "cid",
			ClientSecret: "csec",
			Code:         "auth-code-xyz",
			CodeVerifier: "verifier-abc",
			GrantType:    "authorization_code",
		})
		oauthtest.WriteJSON(t, w, map[string]any{
			"access_token": "ms.test",
			"expires_in":   3600,
			"token_type":   "Bearer",
			"scope":        "openid email profile",
			"id_token":     "stub",
		})
	})
	p := msprov.New(msprov.Config{
		ClientID:     "cid",
		ClientSecret: "csec",
		TokenURL:     srv.URL + "/token",
	})
	before := time.Now()
	tok, err := p.ExchangeCode(context.Background(), "auth-code-xyz", "verifier-abc", "https://r")
	if err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken != "ms.test" {
		t.Fatalf("AccessToken = %q", tok.AccessToken)
	}
	if tok.TokenType != "Bearer" {
		t.Fatalf("TokenType = %q", tok.TokenType)
	}
	if tok.Scope != "openid email profile" {
		t.Fatalf("Scope = %q", tok.Scope)
	}
	wantExpiry := before.Add(3600 * time.Second)
	if delta := tok.ExpiresAt.Sub(wantExpiry); delta < -5*time.Second || delta > 5*time.Second {
		t.Fatalf("ExpiresAt = %v, want within 5s of %v", tok.ExpiresAt, wantExpiry)
	}
}

func TestExchangeCodePostsToTenantTokenURL(t *testing.T) {
	mux, srv := oauthtest.NewMux(t)
	var gotPath string
	mux.HandleFunc("/contoso.onmicrosoft.com/oauth2/v2.0/token", func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		oauthtest.WriteJSON(t, w, map[string]any{
			"access_token": "ms",
			"expires_in":   3600,
			"token_type":   "Bearer",
		})
	})
	p := msprov.New(msprov.Config{
		ClientID:     "cid",
		ClientSecret: "csec",
		Tenant:       "contoso.onmicrosoft.com",
		// We point both AuthorizeURL and TokenURL to the mock so the
		// tenant substitution path is exercised end to end.
		AuthorizeURL: srv.URL + "/contoso.onmicrosoft.com/oauth2/v2.0/authorize",
		TokenURL:     srv.URL + "/contoso.onmicrosoft.com/oauth2/v2.0/token",
	})
	if _, err := p.ExchangeCode(context.Background(), "c", "v", "https://r"); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/contoso.onmicrosoft.com/oauth2/v2.0/token" {
		t.Fatalf("token request landed on %q, want tenant-substituted path", gotPath)
	}
}

func TestUserInfoMapsFields(t *testing.T) {
	mux, srv := oauthtest.NewMux(t)
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		oauthtest.AssertBearer(t, r, "ms.test")
		oauthtest.WriteJSON(t, w, map[string]any{
			"sub":   "AAA-BBB",
			"email": "alice@contoso.com",
			"name":  "Alice Anderson",
		})
	})
	p := msprov.New(msprov.Config{
		ClientID:     "cid",
		ClientSecret: "csec",
		UserInfoURL:  srv.URL + "/userinfo",
	})
	u, err := p.UserInfo(context.Background(), &theauth.ProviderToken{AccessToken: "ms.test"})
	if err != nil {
		t.Fatal(err)
	}
	if u.ID != "AAA-BBB" {
		t.Fatalf("ID = %q", u.ID)
	}
	if u.Email != "alice@contoso.com" {
		t.Fatalf("Email = %q", u.Email)
	}
	if u.EmailVerified {
		t.Fatal("EmailVerified must be false for Microsoft")
	}
	if u.Name != "Alice Anderson" {
		t.Fatalf("Name = %q", u.Name)
	}
	if u.AvatarURL != "" {
		t.Fatalf("AvatarURL = %q, want empty for Microsoft v0.4", u.AvatarURL)
	}
}

func TestUserInfoFallsBackToPreferredUsernameWhenEmailEmpty(t *testing.T) {
	mux, srv := oauthtest.NewMux(t)
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, _ *http.Request) {
		oauthtest.WriteJSON(t, w, map[string]any{
			"sub":                "S",
			"email":              "",
			"preferred_username": "alice@contoso.com",
			"name":               "Alice Anderson",
		})
	})
	p := msprov.New(msprov.Config{
		ClientID:     "cid",
		ClientSecret: "csec",
		UserInfoURL:  srv.URL + "/userinfo",
	})
	u, err := p.UserInfo(context.Background(), &theauth.ProviderToken{AccessToken: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if u.Email != "alice@contoso.com" {
		t.Fatalf("Email = %q, want preferred_username fallback", u.Email)
	}
}

func TestUserInfoFallsBackToPreferredUsernameForName(t *testing.T) {
	mux, srv := oauthtest.NewMux(t)
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, _ *http.Request) {
		oauthtest.WriteJSON(t, w, map[string]any{
			"sub":                "S",
			"email":              "alice@contoso.com",
			"name":               "",
			"preferred_username": "alice@contoso.com",
		})
	})
	p := msprov.New(msprov.Config{
		ClientID:     "cid",
		ClientSecret: "csec",
		UserInfoURL:  srv.URL + "/userinfo",
	})
	u, err := p.UserInfo(context.Background(), &theauth.ProviderToken{AccessToken: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if u.Name != "alice@contoso.com" {
		t.Fatalf("Name = %q, want preferred_username fallback", u.Name)
	}
}

func TestUserInfoEmailVerifiedAlwaysFalse(t *testing.T) {
	mux, srv := oauthtest.NewMux(t)
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, _ *http.Request) {
		oauthtest.WriteJSON(t, w, map[string]any{
			"sub":   "S",
			"email": "alice@contoso.com",
			"name":  "Alice",
		})
	})
	p := msprov.New(msprov.Config{
		ClientID:     "cid",
		ClientSecret: "csec",
		UserInfoURL:  srv.URL + "/userinfo",
	})
	u, err := p.UserInfo(context.Background(), &theauth.ProviderToken{AccessToken: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if u.EmailVerified {
		t.Fatal("EmailVerified must be false for Microsoft OIDC endpoint")
	}
}

func TestUserInfoIDIsSubNotOID(t *testing.T) {
	mux, srv := oauthtest.NewMux(t)
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, _ *http.Request) {
		oauthtest.WriteJSON(t, w, map[string]any{
			"sub":   "stable-app-subject",
			"oid":   "user-object-id",
			"email": "alice@contoso.com",
			"name":  "Alice",
		})
	})
	p := msprov.New(msprov.Config{
		ClientID:     "cid",
		ClientSecret: "csec",
		UserInfoURL:  srv.URL + "/userinfo",
	})
	u, err := p.UserInfo(context.Background(), &theauth.ProviderToken{AccessToken: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if u.ID != "stable-app-subject" {
		t.Fatalf("ID = %q, want sub (not oid)", u.ID)
	}
}
