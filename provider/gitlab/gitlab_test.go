package gitlab_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/glincker/theauth-go"
	glprov "github.com/glincker/theauth-go/provider/gitlab"
)

func TestNameIsGitLab(t *testing.T) {
	p := glprov.New(glprov.Config{ClientID: "x", ClientSecret: "y"})
	if got := p.Name(); got != "gitlab" {
		t.Fatalf("Name() = %q, want %q", got, "gitlab")
	}
}

func TestAuthURLDefaultsToGitLabCom(t *testing.T) {
	p := glprov.New(glprov.Config{ClientID: "cid", ClientSecret: "csec"})
	got := p.AuthURL("state", "challenge", "https://r", nil)
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("AuthURL not parseable: %v", err)
	}
	if u.Host != "gitlab.com" {
		t.Fatalf("expected gitlab.com host, got %q", u.Host)
	}
}

func TestAuthURLUsesBaseURL(t *testing.T) {
	p := glprov.New(glprov.Config{
		ClientID:     "cid",
		ClientSecret: "csec",
		BaseURL:      "https://git.example.com",
	})
	got := p.AuthURL("state", "challenge", "https://r", nil)
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("AuthURL not parseable: %v", err)
	}
	if u.Host != "git.example.com" {
		t.Fatalf("expected git.example.com host, got %q", u.Host)
	}
}

func TestAuthURLContainsPKCEParams(t *testing.T) {
	p := glprov.New(glprov.Config{ClientID: "cid", ClientSecret: "csec"})
	got := p.AuthURL("s", "challenge-abc", "https://r", nil)
	u, _ := url.Parse(got)
	q := u.Query()
	if q.Get("code_challenge") != "challenge-abc" {
		t.Fatalf("code_challenge missing: %s", got)
	}
	if q.Get("code_challenge_method") != "S256" {
		t.Fatalf("code_challenge_method missing: %s", got)
	}
}

func mockGitLab(t *testing.T, accessToken, sub, email, name, picture string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  accessToken,
			"token_type":    "Bearer",
			"expires_in":    7200,
			"refresh_token": "test-refresh",
		})
	})

	mux.HandleFunc("/oauth/userinfo", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
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
	srv := mockGitLab(t, "glpat-test-token", "", "", "", "")
	p := glprov.New(glprov.Config{
		ClientID:     "cid",
		ClientSecret: "csec",
		TokenURL:     srv.URL + "/oauth/token",
		UserInfoURL:  srv.URL + "/oauth/userinfo",
	})
	tok, err := p.ExchangeCode(context.Background(), "code", "verifier", "https://r")
	if err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken != "glpat-test-token" {
		t.Fatalf("AccessToken = %q", tok.AccessToken)
	}
	if tok.RefreshToken != "test-refresh" {
		t.Fatalf("RefreshToken = %q", tok.RefreshToken)
	}
}

func TestUserInfoMapsFields(t *testing.T) {
	srv := mockGitLab(t, "glpat-test-token", "42", "user@gitlab.com", "Test User", "https://secure.gravatar.com/avatar/test")
	p := glprov.New(glprov.Config{
		ClientID:     "cid",
		ClientSecret: "csec",
		TokenURL:     srv.URL + "/oauth/token",
		UserInfoURL:  srv.URL + "/oauth/userinfo",
	})
	user, err := p.UserInfo(context.Background(), &theauth.ProviderToken{AccessToken: "glpat-test-token"})
	if err != nil {
		t.Fatal(err)
	}
	if user.ID != "42" {
		t.Fatalf("ID = %q, want %q", user.ID, "42")
	}
	if user.Email != "user@gitlab.com" {
		t.Fatalf("Email = %q", user.Email)
	}
	if !user.EmailVerified {
		t.Fatal("EmailVerified should be true")
	}
	if user.Name != "Test User" {
		t.Fatalf("Name = %q", user.Name)
	}
}
