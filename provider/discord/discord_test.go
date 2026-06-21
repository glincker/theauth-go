package discord_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/glincker/theauth-go"
	discprov "github.com/glincker/theauth-go/provider/discord"
	"github.com/glincker/theauth-go/provider/internal/oauthtest"
)

func TestNameIsDiscord(t *testing.T) {
	p := discprov.New(discprov.Config{ClientID: "x", ClientSecret: "y"})
	if got := p.Name(); got != "discord" {
		t.Fatalf("Name() = %q, want %q", got, "discord")
	}
}

func TestAuthURLContainsRequiredParams(t *testing.T) {
	p := discprov.New(discprov.Config{ClientID: "client-abc", ClientSecret: "shh"})
	got := p.AuthURL("state-xyz", "challenge-123", "https://app.example.com/auth/providers/discord/callback", []string{"identify", "email"})
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("AuthURL not parseable: %v", err)
	}
	if u.Host != "discord.com" || u.Path != "/api/oauth2/authorize" {
		t.Fatalf("unexpected URL: %s", got)
	}
	q := u.Query()
	wantParams := map[string]string{
		"client_id":             "client-abc",
		"redirect_uri":          "https://app.example.com/auth/providers/discord/callback",
		"response_type":         "code",
		"scope":                 "identify email",
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
	p := discprov.New(discprov.Config{ClientID: "x", ClientSecret: "y"})
	u, _ := url.Parse(p.AuthURL("s", "c", "https://r", nil))
	if got := u.Query().Get("scope"); got != "identify email" {
		t.Fatalf("default scope = %q, want %q", got, "identify email")
	}
}

func TestExchangeCodeParsesTokenResponse(t *testing.T) {
	mux, srv := oauthtest.NewMux(t)
	mux.HandleFunc("/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		oauthtest.AssertTokenForm(t, r, oauthtest.TokenExpect{
			ClientID:     "cid",
			ClientSecret: "csec",
			Code:         "auth-code-xyz",
			CodeVerifier: "verifier-abc",
			GrantType:    "authorization_code",
		})
		oauthtest.WriteJSON(t, w, map[string]any{
			"access_token":  "disc.test",
			"refresh_token": "disc.refresh",
			"expires_in":    604800,
			"token_type":    "Bearer",
			"scope":         "identify email",
		})
	})
	p := discprov.New(discprov.Config{
		ClientID:     "cid",
		ClientSecret: "csec",
		TokenURL:     srv.URL + "/oauth2/token",
	})
	before := time.Now()
	tok, err := p.ExchangeCode(context.Background(), "auth-code-xyz", "verifier-abc", "https://r")
	if err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken != "disc.test" {
		t.Fatalf("AccessToken = %q", tok.AccessToken)
	}
	if tok.RefreshToken != "disc.refresh" {
		t.Fatalf("RefreshToken = %q, want disc.refresh", tok.RefreshToken)
	}
	if tok.TokenType != "Bearer" {
		t.Fatalf("TokenType = %q", tok.TokenType)
	}
	if tok.Scope != "identify email" {
		t.Fatalf("Scope = %q", tok.Scope)
	}
	wantExpiry := before.Add(604800 * time.Second)
	if delta := tok.ExpiresAt.Sub(wantExpiry); delta < -5*time.Second || delta > 5*time.Second {
		t.Fatalf("ExpiresAt = %v, want within 5s of %v", tok.ExpiresAt, wantExpiry)
	}
}

func TestExchangeCodeReturnsErrorOnNon2xx(t *testing.T) {
	mux, srv := oauthtest.NewMux(t)
	mux.HandleFunc("/oauth2/token", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_request"}`))
	})
	p := discprov.New(discprov.Config{
		ClientID:     "cid",
		ClientSecret: "csec",
		TokenURL:     srv.URL + "/oauth2/token",
	})
	_, err := p.ExchangeCode(context.Background(), "x", "y", "https://r")
	if err == nil {
		t.Fatal("expected error on 400")
	}
	if !strings.Contains(err.Error(), "invalid_request") {
		t.Fatalf("error %q does not contain invalid_request", err.Error())
	}
}

func TestUserInfoMapsFields(t *testing.T) {
	mux, srv := oauthtest.NewMux(t)
	mux.HandleFunc("/users/@me", func(w http.ResponseWriter, r *http.Request) {
		oauthtest.AssertBearer(t, r, "disc.test")
		oauthtest.WriteJSON(t, w, map[string]any{
			"id":          "80351110224678912",
			"username":    "nelly",
			"global_name": "Nelly",
			"avatar":      "8342729096ea3675442027381ff50dfe",
			"email":       "nelly@example.com",
			"verified":    true,
		})
	})
	p := discprov.New(discprov.Config{
		ClientID:     "cid",
		ClientSecret: "csec",
		UserInfoURL:  srv.URL + "/users/@me",
	})
	u, err := p.UserInfo(context.Background(), &theauth.ProviderToken{AccessToken: "disc.test"})
	if err != nil {
		t.Fatal(err)
	}
	if u.ID != "80351110224678912" {
		t.Fatalf("ID = %q", u.ID)
	}
	if u.Email != "nelly@example.com" {
		t.Fatalf("Email = %q", u.Email)
	}
	if !u.EmailVerified {
		t.Fatal("EmailVerified should be true")
	}
	if u.Name != "Nelly" {
		t.Fatalf("Name = %q", u.Name)
	}
	want := "https://cdn.discordapp.com/avatars/80351110224678912/8342729096ea3675442027381ff50dfe.png"
	if u.AvatarURL != want {
		t.Fatalf("AvatarURL = %q, want %q", u.AvatarURL, want)
	}
}

func TestUserInfoFallsBackToUsername(t *testing.T) {
	mux, srv := oauthtest.NewMux(t)
	mux.HandleFunc("/users/@me", func(w http.ResponseWriter, _ *http.Request) {
		oauthtest.WriteJSON(t, w, map[string]any{
			"id":          "1",
			"username":    "nelly",
			"global_name": "",
			"email":       "nelly@example.com",
			"verified":    true,
		})
	})
	p := discprov.New(discprov.Config{
		ClientID:     "cid",
		ClientSecret: "csec",
		UserInfoURL:  srv.URL + "/users/@me",
	})
	u, err := p.UserInfo(context.Background(), &theauth.ProviderToken{AccessToken: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if u.Name != "nelly" {
		t.Fatalf("Name = %q, want %q", u.Name, "nelly")
	}
}

func TestUserInfoEmptyAvatarYieldsEmptyURL(t *testing.T) {
	mux, srv := oauthtest.NewMux(t)
	mux.HandleFunc("/users/@me", func(w http.ResponseWriter, _ *http.Request) {
		oauthtest.WriteJSON(t, w, map[string]any{
			"id":          "1",
			"username":    "nelly",
			"global_name": "Nelly",
			"avatar":      "",
			"email":       "nelly@example.com",
			"verified":    true,
		})
	})
	p := discprov.New(discprov.Config{
		ClientID:     "cid",
		ClientSecret: "csec",
		UserInfoURL:  srv.URL + "/users/@me",
	})
	u, err := p.UserInfo(context.Background(), &theauth.ProviderToken{AccessToken: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if u.AvatarURL != "" {
		t.Fatalf("AvatarURL = %q, want empty when avatar hash is empty", u.AvatarURL)
	}
}

func TestUserInfoVerifiedFalseMapsThrough(t *testing.T) {
	mux, srv := oauthtest.NewMux(t)
	mux.HandleFunc("/users/@me", func(w http.ResponseWriter, _ *http.Request) {
		oauthtest.WriteJSON(t, w, map[string]any{
			"id":       "1",
			"username": "nelly",
			"email":    "nelly@example.com",
			"verified": false,
		})
	})
	p := discprov.New(discprov.Config{
		ClientID:     "cid",
		ClientSecret: "csec",
		UserInfoURL:  srv.URL + "/users/@me",
	})
	u, err := p.UserInfo(context.Background(), &theauth.ProviderToken{AccessToken: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if u.EmailVerified {
		t.Fatal("EmailVerified should be false")
	}
}

func TestUserInfoEmailMissingScopeYieldsEmptyEmail(t *testing.T) {
	mux, srv := oauthtest.NewMux(t)
	mux.HandleFunc("/users/@me", func(w http.ResponseWriter, _ *http.Request) {
		// No email field at all (user denied the email scope).
		oauthtest.WriteJSON(t, w, map[string]any{
			"id":       "1",
			"username": "nelly",
		})
	})
	p := discprov.New(discprov.Config{
		ClientID:     "cid",
		ClientSecret: "csec",
		UserInfoURL:  srv.URL + "/users/@me",
	})
	u, err := p.UserInfo(context.Background(), &theauth.ProviderToken{AccessToken: "t"})
	if err != nil {
		t.Fatalf("expected no error when email is omitted, got %v", err)
	}
	if u.Email != "" {
		t.Fatalf("Email = %q, want empty when scope was denied", u.Email)
	}
}
