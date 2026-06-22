package twitch_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/glincker/theauth-go"
	twitchprov "github.com/glincker/theauth-go/provider/twitch"
)

func TestNameIsTwitch(t *testing.T) {
	p := twitchprov.New(twitchprov.Config{ClientID: "x", ClientSecret: "y"})
	if got := p.Name(); got != "twitch" {
		t.Fatalf("Name() = %q, want %q", got, "twitch")
	}
}

func TestAuthURLContainsRequiredParams(t *testing.T) {
	p := twitchprov.New(twitchprov.Config{ClientID: "twitch-client", ClientSecret: "shh"})
	got := p.AuthURL("state-xyz", "challenge-123", "https://app.example.com/callback", nil)
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("AuthURL not parseable: %v", err)
	}
	q := u.Query()
	if q.Get("client_id") != "twitch-client" {
		t.Fatalf("client_id missing: %s", got)
	}
	if q.Get("code_challenge_method") != "S256" {
		t.Fatalf("code_challenge_method missing: %s", got)
	}
	if q.Get("claims") == "" {
		t.Fatalf("claims param missing (required for email in userinfo): %s", got)
	}
}

func mockTwitch(t *testing.T, accessToken, sub, email, name, picture string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  accessToken,
			"token_type":    "bearer",
			"expires_in":    14400,
			"refresh_token": "refresh-token-abc",
			"scope":         []string{"openid", "user:read:email"},
		})
	})

	mux.HandleFunc("/oauth2/userinfo", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"sub":                sub,
			"email":              email,
			"email_verified":     true,
			"preferred_username": name,
			"picture":            picture,
		})
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestExchangeCodeParsesToken(t *testing.T) {
	srv := mockTwitch(t, "twitch-oauth-token", "", "", "", "")
	p := twitchprov.New(twitchprov.Config{
		ClientID:     "cid",
		ClientSecret: "csec",
		TokenURL:     srv.URL + "/oauth2/token",
		UserInfoURL:  srv.URL + "/oauth2/userinfo",
	})
	tok, err := p.ExchangeCode(context.Background(), "code", "verifier", "https://r")
	if err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken != "twitch-oauth-token" {
		t.Fatalf("AccessToken = %q", tok.AccessToken)
	}
	if tok.RefreshToken != "refresh-token-abc" {
		t.Fatalf("RefreshToken = %q", tok.RefreshToken)
	}
}

func TestUserInfoMapsFields(t *testing.T) {
	srv := mockTwitch(t, "twitch-token", "123456789", "streamer@example.com", "TheStreamer", "https://static-cdn.jtvnw.net/jtv_user_pictures/test.png")
	p := twitchprov.New(twitchprov.Config{
		ClientID:     "cid",
		ClientSecret: "csec",
		TokenURL:     srv.URL + "/oauth2/token",
		UserInfoURL:  srv.URL + "/oauth2/userinfo",
	})
	user, err := p.UserInfo(context.Background(), &theauth.ProviderToken{AccessToken: "twitch-token"})
	if err != nil {
		t.Fatal(err)
	}
	if user.ID != "123456789" {
		t.Fatalf("ID = %q", user.ID)
	}
	if user.Email != "streamer@example.com" {
		t.Fatalf("Email = %q", user.Email)
	}
	if !user.EmailVerified {
		t.Fatal("EmailVerified should be true")
	}
	if user.Name != "TheStreamer" {
		t.Fatalf("Name = %q", user.Name)
	}
}

func TestUserInfoMissingTokenErrors(t *testing.T) {
	p := twitchprov.New(twitchprov.Config{ClientID: "x", ClientSecret: "y"})
	_, err := p.UserInfo(context.Background(), &theauth.ProviderToken{})
	if err == nil {
		t.Fatal("expected error for empty access token")
	}
}
