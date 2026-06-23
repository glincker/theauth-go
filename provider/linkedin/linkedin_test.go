package linkedin_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/glincker/theauth-go"
	liprov "github.com/glincker/theauth-go/provider/linkedin"
)

func TestNameIsLinkedIn(t *testing.T) {
	p := liprov.New(liprov.Config{ClientID: "x", ClientSecret: "y"})
	if got := p.Name(); got != "linkedin" {
		t.Fatalf("Name() = %q, want %q", got, "linkedin")
	}
}

func TestAuthURLContainsRequiredParams(t *testing.T) {
	p := liprov.New(liprov.Config{ClientID: "li-client", ClientSecret: "shh"})
	got := p.AuthURL("state-xyz", "challenge-123", "https://app.example.com/callback", nil)
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("AuthURL not parseable: %v", err)
	}
	q := u.Query()
	if q.Get("client_id") != "li-client" {
		t.Fatalf("client_id missing: %s", got)
	}
	if q.Get("code_challenge_method") != "S256" {
		t.Fatalf("code_challenge_method missing: %s", got)
	}
	if q.Get("state") != "state-xyz" {
		t.Fatalf("state missing: %s", got)
	}
}

func mockLinkedIn(t *testing.T, accessToken, sub, email, name, picture string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/oauth/v2/accessToken", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": accessToken,
			"token_type":   "Bearer",
			"expires_in":   5183944,
			"scope":        "openid email profile",
		})
	})

	mux.HandleFunc("/v2/userinfo", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"sub":            sub,
			"email":          email,
			"email_verified": true,
			"name":           name,
			"given_name":     "Test",
			"family_name":    "User",
			"picture":        picture,
		})
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestExchangeCodeParsesToken(t *testing.T) {
	srv := mockLinkedIn(t, "li-access-token", "", "", "", "")
	p := liprov.New(liprov.Config{
		ClientID:     "cid",
		ClientSecret: "csec",
		TokenURL:     srv.URL + "/oauth/v2/accessToken",
		UserInfoURL:  srv.URL + "/v2/userinfo",
	})
	tok, err := p.ExchangeCode(context.Background(), "code", "verifier", "https://r")
	if err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken != "li-access-token" {
		t.Fatalf("AccessToken = %q", tok.AccessToken)
	}
}

func TestUserInfoMapsFields(t *testing.T) {
	srv := mockLinkedIn(t, "li-token", "sub-xyz", "user@linkedin.com", "Test User", "https://media.licdn.com/dms/image/test.jpg")
	p := liprov.New(liprov.Config{
		ClientID:     "cid",
		ClientSecret: "csec",
		TokenURL:     srv.URL + "/oauth/v2/accessToken",
		UserInfoURL:  srv.URL + "/v2/userinfo",
	})
	user, err := p.UserInfo(context.Background(), &theauth.ProviderToken{AccessToken: "li-token"})
	if err != nil {
		t.Fatal(err)
	}
	if user.ID != "sub-xyz" {
		t.Fatalf("ID = %q", user.ID)
	}
	if user.Email != "user@linkedin.com" {
		t.Fatalf("Email = %q", user.Email)
	}
	if !user.EmailVerified {
		t.Fatal("EmailVerified should be true")
	}
	if user.Name != "Test User" {
		t.Fatalf("Name = %q", user.Name)
	}
}

func TestUserInfoMissingTokenErrors(t *testing.T) {
	p := liprov.New(liprov.Config{ClientID: "x", ClientSecret: "y"})
	_, err := p.UserInfo(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil token")
	}
}
