package google_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/glincker/theauth-go"
	googprov "github.com/glincker/theauth-go/provider/google"
	"github.com/glincker/theauth-go/provider/internal/oauthtest"
)

func TestNameIsGoogle(t *testing.T) {
	p := googprov.New(googprov.Config{ClientID: "x", ClientSecret: "y"})
	if got := p.Name(); got != "google" {
		t.Fatalf("Name() = %q, want %q", got, "google")
	}
}

func TestAuthURLContainsRequiredParams(t *testing.T) {
	p := googprov.New(googprov.Config{
		ClientID:     "client-abc",
		ClientSecret: "shh",
	})
	got := p.AuthURL("state-xyz", "challenge-123", "https://app.example.com/auth/providers/google/callback", []string{"openid", "email", "profile"})
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("AuthURL not parseable: %v", err)
	}
	if u.Host != "accounts.google.com" || u.Path != "/o/oauth2/v2/auth" {
		t.Fatalf("unexpected URL: %s", got)
	}
	q := u.Query()
	wantParams := map[string]string{
		"client_id":             "client-abc",
		"redirect_uri":          "https://app.example.com/auth/providers/google/callback",
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
	p := googprov.New(googprov.Config{ClientID: "x", ClientSecret: "y"})
	u, _ := url.Parse(p.AuthURL("s", "c", "https://r", nil))
	if got := u.Query().Get("scope"); got != "openid email profile" {
		t.Fatalf("default scope = %q, want %q", got, "openid email profile")
	}
}

func TestAuthURLAcceptsCustomScopes(t *testing.T) {
	p := googprov.New(googprov.Config{ClientID: "x", ClientSecret: "y"})
	custom := []string{"openid", "email", "profile", "https://www.googleapis.com/auth/calendar.readonly"}
	u, _ := url.Parse(p.AuthURL("s", "c", "https://r", custom))
	want := "openid email profile https://www.googleapis.com/auth/calendar.readonly"
	if got := u.Query().Get("scope"); got != want {
		t.Fatalf("scope = %q, want %q", got, want)
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
			"access_token": "ya29.test",
			"expires_in":   3599,
			"token_type":   "Bearer",
			"scope":        "openid email profile",
			"id_token":     "stub",
		})
	})
	p := googprov.New(googprov.Config{
		ClientID:     "cid",
		ClientSecret: "csec",
		TokenURL:     srv.URL + "/token",
	})
	before := time.Now()
	tok, err := p.ExchangeCode(context.Background(), "auth-code-xyz", "verifier-abc", "https://r")
	if err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken != "ya29.test" {
		t.Fatalf("AccessToken = %q", tok.AccessToken)
	}
	if tok.TokenType != "Bearer" {
		t.Fatalf("TokenType = %q", tok.TokenType)
	}
	if tok.Scope != "openid email profile" {
		t.Fatalf("Scope = %q", tok.Scope)
	}
	wantExpiry := before.Add(3599 * time.Second)
	if delta := tok.ExpiresAt.Sub(wantExpiry); delta < -5*time.Second || delta > 5*time.Second {
		t.Fatalf("ExpiresAt = %v, want within 5s of %v", tok.ExpiresAt, wantExpiry)
	}
}

func TestExchangeCodeReturnsErrorOnNon2xx(t *testing.T) {
	mux, srv := oauthtest.NewMux(t)
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"bad code"}`))
	})
	p := googprov.New(googprov.Config{
		ClientID:     "cid",
		ClientSecret: "csec",
		TokenURL:     srv.URL + "/token",
	})
	_, err := p.ExchangeCode(context.Background(), "x", "y", "https://r")
	if err == nil {
		t.Fatal("expected error on 400")
	}
	if !strings.Contains(err.Error(), "invalid_grant") || !strings.Contains(err.Error(), "bad code") {
		t.Fatalf("error %q does not contain both invalid_grant and bad code", err.Error())
	}
}

func TestUserInfoMapsFields(t *testing.T) {
	mux, srv := oauthtest.NewMux(t)
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		oauthtest.AssertBearer(t, r, "ya29.test")
		oauthtest.WriteJSON(t, w, map[string]any{
			"sub":            "1234567890",
			"email":          "alice@example.com",
			"email_verified": true,
			"name":           "Alice",
			"picture":        "https://lh3.googleusercontent.com/a/x",
		})
	})
	p := googprov.New(googprov.Config{
		ClientID:     "cid",
		ClientSecret: "csec",
		UserInfoURL:  srv.URL + "/userinfo",
	})
	u, err := p.UserInfo(context.Background(), &theauth.ProviderToken{AccessToken: "ya29.test"})
	if err != nil {
		t.Fatal(err)
	}
	if u.ID != "1234567890" {
		t.Fatalf("ID = %q", u.ID)
	}
	if u.Email != "alice@example.com" {
		t.Fatalf("Email = %q", u.Email)
	}
	if !u.EmailVerified {
		t.Fatal("EmailVerified should be true")
	}
	if u.Name != "Alice" {
		t.Fatalf("Name = %q", u.Name)
	}
	if u.AvatarURL != "https://lh3.googleusercontent.com/a/x" {
		t.Fatalf("AvatarURL = %q", u.AvatarURL)
	}
}

func TestUserInfoNameFallsBackToGivenFamily(t *testing.T) {
	mux, srv := oauthtest.NewMux(t)
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, _ *http.Request) {
		oauthtest.WriteJSON(t, w, map[string]any{
			"sub":         "1",
			"email":       "alice@example.com",
			"name":        "",
			"given_name":  "Alice",
			"family_name": "Liddell",
		})
	})
	p := googprov.New(googprov.Config{
		ClientID:     "cid",
		ClientSecret: "csec",
		UserInfoURL:  srv.URL + "/userinfo",
	})
	u, err := p.UserInfo(context.Background(), &theauth.ProviderToken{AccessToken: "tok"})
	if err != nil {
		t.Fatal(err)
	}
	if u.Name != "Alice Liddell" {
		t.Fatalf("Name = %q, want %q", u.Name, "Alice Liddell")
	}
}

func TestUserInfoNameFallsBackToEmailLocalPart(t *testing.T) {
	mux, srv := oauthtest.NewMux(t)
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, _ *http.Request) {
		oauthtest.WriteJSON(t, w, map[string]any{
			"sub":         "1",
			"email":       "alice@example.com",
			"name":        "",
			"given_name":  "",
			"family_name": "",
		})
	})
	p := googprov.New(googprov.Config{
		ClientID:     "cid",
		ClientSecret: "csec",
		UserInfoURL:  srv.URL + "/userinfo",
	})
	u, err := p.UserInfo(context.Background(), &theauth.ProviderToken{AccessToken: "tok"})
	if err != nil {
		t.Fatal(err)
	}
	if u.Name != "alice" {
		t.Fatalf("Name = %q, want %q", u.Name, "alice")
	}
}

func TestUserInfoEmailVerifiedFalse(t *testing.T) {
	mux, srv := oauthtest.NewMux(t)
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, _ *http.Request) {
		oauthtest.WriteJSON(t, w, map[string]any{
			"sub":            "1",
			"email":          "x@example.com",
			"email_verified": false,
			"name":           "X",
		})
	})
	p := googprov.New(googprov.Config{
		ClientID:     "cid",
		ClientSecret: "csec",
		UserInfoURL:  srv.URL + "/userinfo",
	})
	u, err := p.UserInfo(context.Background(), &theauth.ProviderToken{AccessToken: "tok"})
	if err != nil {
		t.Fatal(err)
	}
	if u.EmailVerified {
		t.Fatal("EmailVerified should be false")
	}
}
