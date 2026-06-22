package x_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/glincker/theauth-go"
	xprov "github.com/glincker/theauth-go/provider/x"
)

func TestNameIsX(t *testing.T) {
	p := xprov.New(xprov.Config{ClientID: "cid", ClientSecret: "csec"})
	if got := p.Name(); got != "x" {
		t.Fatalf("Name() = %q, want %q", got, "x")
	}
}

func TestAuthURLContainsPKCEParams(t *testing.T) {
	p := xprov.New(xprov.Config{ClientID: "x-client", ClientSecret: "shh"})
	got := p.AuthURL("state-xyz", "challenge-abc", "https://app.example.com/callback", nil)
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("AuthURL not parseable: %v", err)
	}
	q := u.Query()
	if q.Get("client_id") != "x-client" {
		t.Fatalf("client_id missing: %s", got)
	}
	if q.Get("code_challenge") != "challenge-abc" {
		t.Fatalf("code_challenge missing: %s", got)
	}
	if q.Get("code_challenge_method") != "S256" {
		t.Fatalf("code_challenge_method must be S256 (mandatory): %s", got)
	}
}

func TestExchangeCodeRequiresVerifier(t *testing.T) {
	p := xprov.New(xprov.Config{ClientID: "x", ClientSecret: "y"})
	_, err := p.ExchangeCode(context.Background(), "code", "", "https://r")
	if err == nil {
		t.Fatal("expected error when code_verifier is empty (PKCE mandatory for X)")
	}
}

func mockX(t *testing.T, accessToken, id, name, username, profileImg string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/2/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		// Verify Basic auth for confidential client.
		user, _, ok := r.BasicAuth()
		if !ok || user == "" {
			t.Errorf("expected Basic auth for confidential client")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  accessToken,
			"token_type":    "bearer",
			"expires_in":    7200,
			"refresh_token": "x-refresh-token",
			"scope":         "tweet.read users.read offline.access",
		})
	})

	mux.HandleFunc("/2/users/me", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+accessToken {
			t.Errorf("Authorization header missing or wrong")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"id":                id,
				"name":              name,
				"username":          username,
				"profile_image_url": profileImg,
			},
		})
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestExchangeCodeParsesToken(t *testing.T) {
	srv := mockX(t, "x-oauth-token", "", "", "", "")
	p := xprov.New(xprov.Config{
		ClientID:     "cid",
		ClientSecret: "csec",
		TokenURL:     srv.URL + "/2/oauth2/token",
		UserInfoURL:  srv.URL + "/2/users/me",
	})
	tok, err := p.ExchangeCode(context.Background(), "code", "verifier-abc", "https://r")
	if err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken != "x-oauth-token" {
		t.Fatalf("AccessToken = %q", tok.AccessToken)
	}
	if tok.RefreshToken != "x-refresh-token" {
		t.Fatalf("RefreshToken = %q", tok.RefreshToken)
	}
}

func TestUserInfoMapsFields(t *testing.T) {
	srv := mockX(t, "x-token", "987654321", "Test User", "testuser", "https://pbs.twimg.com/profile_images/test.jpg")
	p := xprov.New(xprov.Config{
		ClientID:     "cid",
		ClientSecret: "csec",
		TokenURL:     srv.URL + "/2/oauth2/token",
		UserInfoURL:  srv.URL + "/2/users/me",
	})
	user, err := p.UserInfo(context.Background(), &theauth.ProviderToken{AccessToken: "x-token"})
	if err != nil {
		t.Fatal(err)
	}
	if user.ID != "987654321" {
		t.Fatalf("ID = %q", user.ID)
	}
	if user.Name != "Test User" {
		t.Fatalf("Name = %q", user.Name)
	}
	if user.AvatarURL != "https://pbs.twimg.com/profile_images/test.jpg" {
		t.Fatalf("AvatarURL = %q", user.AvatarURL)
	}
	// X does not expose email without elevated access.
	if user.Email != "" {
		t.Fatalf("Email should be empty for standard X apps, got %q", user.Email)
	}
}

func TestUserInfoMissingTokenErrors(t *testing.T) {
	p := xprov.New(xprov.Config{ClientID: "x", ClientSecret: "y"})
	_, err := p.UserInfo(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil token")
	}
}
