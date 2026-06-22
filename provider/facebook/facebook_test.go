package facebook_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/glincker/theauth-go"
	fbprov "github.com/glincker/theauth-go/provider/facebook"
)

func TestNameIsFacebook(t *testing.T) {
	p := fbprov.New(fbprov.Config{ClientID: "x", ClientSecret: "y"})
	if got := p.Name(); got != "facebook" {
		t.Fatalf("Name() = %q, want %q", got, "facebook")
	}
}

func TestAuthURLContainsRequiredParams(t *testing.T) {
	p := fbprov.New(fbprov.Config{ClientID: "fb-client", ClientSecret: "shh"})
	got := p.AuthURL("state-xyz", "challenge-123", "https://app.example.com/auth/providers/facebook/callback", nil)
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("AuthURL not parseable: %v", err)
	}
	q := u.Query()
	if q.Get("client_id") != "fb-client" {
		t.Fatalf("client_id missing: %s", got)
	}
	if q.Get("state") != "state-xyz" {
		t.Fatalf("state missing: %s", got)
	}
	if q.Get("code_challenge") != "challenge-123" {
		t.Fatalf("code_challenge missing: %s", got)
	}
	if q.Get("code_challenge_method") != "S256" {
		t.Fatalf("code_challenge_method missing: %s", got)
	}
}

type mockOpts struct {
	accessToken string
	userID      string
	name        string
	email       string
	pictureURL  string
}

func mockFacebook(t *testing.T, opts mockOpts) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/oauth/access_token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": opts.accessToken,
			"token_type":   "bearer",
			"expires_in":   5183944,
		})
	})

	mux.HandleFunc("/me", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":    opts.userID,
			"name":  opts.name,
			"email": opts.email,
			"picture": map[string]any{
				"data": map[string]any{
					"url": opts.pictureURL,
				},
			},
		})
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestExchangeCodeParsesToken(t *testing.T) {
	srv := mockFacebook(t, mockOpts{accessToken: "EAA_test_token"})
	p := fbprov.New(fbprov.Config{
		ClientID:     "cid",
		ClientSecret: "csec",
		TokenURL:     srv.URL + "/oauth/access_token",
		UserInfoURL:  srv.URL + "/me",
	})
	tok, err := p.ExchangeCode(context.Background(), "auth-code", "verifier", "https://r")
	if err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken != "EAA_test_token" {
		t.Fatalf("AccessToken = %q", tok.AccessToken)
	}
}

func TestUserInfoMapsFields(t *testing.T) {
	srv := mockFacebook(t, mockOpts{
		accessToken: "EAA_test_token",
		userID:      "12345",
		name:        "Test User",
		email:       "user@example.com",
		pictureURL:  "https://graph.facebook.com/12345/picture",
	})
	p := fbprov.New(fbprov.Config{
		ClientID:     "cid",
		ClientSecret: "csec",
		TokenURL:     srv.URL + "/oauth/access_token",
		UserInfoURL:  srv.URL + "/me",
	})
	user, err := p.UserInfo(context.Background(), &theauth.ProviderToken{AccessToken: "EAA_test_token"})
	if err != nil {
		t.Fatal(err)
	}
	if user.ID != "12345" {
		t.Fatalf("ID = %q, want %q", user.ID, "12345")
	}
	if user.Name != "Test User" {
		t.Fatalf("Name = %q", user.Name)
	}
	if user.Email != "user@example.com" {
		t.Fatalf("Email = %q", user.Email)
	}
	if user.AvatarURL != "https://graph.facebook.com/12345/picture" {
		t.Fatalf("AvatarURL = %q", user.AvatarURL)
	}
}

func TestUserInfoMissingTokenErrors(t *testing.T) {
	p := fbprov.New(fbprov.Config{ClientID: "x", ClientSecret: "y"})
	_, err := p.UserInfo(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil token")
	}
}
