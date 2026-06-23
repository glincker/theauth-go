package slack_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/glincker/theauth-go"
	slackprov "github.com/glincker/theauth-go/provider/slack"
)

func TestNameIsSlack(t *testing.T) {
	p := slackprov.New(slackprov.Config{ClientID: "x", ClientSecret: "y"})
	if got := p.Name(); got != "slack" {
		t.Fatalf("Name() = %q, want %q", got, "slack")
	}
}

func TestAuthURLContainsRequiredParams(t *testing.T) {
	p := slackprov.New(slackprov.Config{ClientID: "slack-client", ClientSecret: "shh"})
	got := p.AuthURL("state-xyz", "challenge-123", "https://app.example.com/auth/providers/slack/callback", nil)
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("AuthURL not parseable: %v", err)
	}
	q := u.Query()
	if q.Get("client_id") != "slack-client" {
		t.Fatalf("client_id missing: %s", got)
	}
	if q.Get("code_challenge_method") != "S256" {
		t.Fatalf("code_challenge_method missing: %s", got)
	}
	if q.Get("scope") == "" {
		t.Fatalf("scope missing: %s", got)
	}
}

func mockSlack(t *testing.T, accessToken, sub, email, name, picture string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/api/openid.connect.token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":           true,
			"access_token": accessToken,
			"token_type":   "Bearer",
			"scope":        "openid email profile",
		})
	})

	mux.HandleFunc("/api/openid.connect.userInfo", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":             true,
			"sub":            sub,
			"email":          email,
			"email_verified": true,
			"name":           name,
			"picture":        picture,
		})
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestExchangeCodeParsesToken(t *testing.T) {
	srv := mockSlack(t, "xoxp-test-token", "", "", "", "")
	p := slackprov.New(slackprov.Config{
		ClientID:     "cid",
		ClientSecret: "csec",
		TokenURL:     srv.URL + "/api/openid.connect.token",
		UserInfoURL:  srv.URL + "/api/openid.connect.userInfo",
	})
	tok, err := p.ExchangeCode(context.Background(), "code", "verifier", "https://r")
	if err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken != "xoxp-test-token" {
		t.Fatalf("AccessToken = %q", tok.AccessToken)
	}
}

func TestUserInfoMapsFields(t *testing.T) {
	srv := mockSlack(t, "xoxp-test-token", "U12345", "user@slack.com", "Test User", "https://avatars.slack-edge.com/test.jpg")
	p := slackprov.New(slackprov.Config{
		ClientID:     "cid",
		ClientSecret: "csec",
		TokenURL:     srv.URL + "/api/openid.connect.token",
		UserInfoURL:  srv.URL + "/api/openid.connect.userInfo",
	})
	user, err := p.UserInfo(context.Background(), &theauth.ProviderToken{AccessToken: "xoxp-test-token"})
	if err != nil {
		t.Fatal(err)
	}
	if user.ID != "U12345" {
		t.Fatalf("ID = %q", user.ID)
	}
	if user.Email != "user@slack.com" {
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
	p := slackprov.New(slackprov.Config{ClientID: "x", ClientSecret: "y"})
	_, err := p.UserInfo(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil token")
	}
}
