package github_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/glincker/theauth-go"
	ghprov "github.com/glincker/theauth-go/provider/github"
)

func TestNameIsGitHub(t *testing.T) {
	p := ghprov.New(ghprov.Config{ClientID: "x", ClientSecret: "y"})
	if got := p.Name(); got != "github" {
		t.Fatalf("Name() = %q, want %q", got, "github")
	}
}

func TestAuthURLContainsRequiredParams(t *testing.T) {
	p := ghprov.New(ghprov.Config{
		ClientID:     "client-abc",
		ClientSecret: "shh",
	})
	got := p.AuthURL("state-xyz", "challenge-123", "https://app.example.com/auth/providers/github/callback", []string{"read:user", "user:email"})
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("AuthURL not parseable: %v", err)
	}
	if u.Host != "github.com" || u.Path != "/login/oauth/authorize" {
		t.Fatalf("unexpected URL: %s", got)
	}
	q := u.Query()
	wantParams := map[string]string{
		"client_id":             "client-abc",
		"redirect_uri":          "https://app.example.com/auth/providers/github/callback",
		"state":                 "state-xyz",
		"code_challenge":        "challenge-123",
		"code_challenge_method": "S256",
		"scope":                 "read:user user:email",
		"response_type":         "code",
	}
	for k, want := range wantParams {
		if got := q.Get(k); got != want {
			t.Fatalf("AuthURL param %q = %q, want %q (full: %s)", k, got, want, got)
		}
	}
}

func TestAuthURLDefaultsScopes(t *testing.T) {
	p := ghprov.New(ghprov.Config{ClientID: "x", ClientSecret: "y"})
	u, _ := url.Parse(p.AuthURL("s", "c", "https://r", nil))
	got := u.Query().Get("scope")
	if got != "read:user user:email" {
		t.Fatalf("default scope = %q, want %q", got, "read:user user:email")
	}
}

// mockGitHub returns an httptest server that handles the three GitHub endpoints
// (token exchange, /user, /user/emails) plus an /authorize stub. Caller picks
// up the URL via .URL and points the provider's endpoints there.
func mockGitHub(t *testing.T, opts mockOpts) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/login/oauth/access_token", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") != "application/json" {
			t.Errorf("expected Accept: application/json; got %q", r.Header.Get("Accept"))
		}
		_ = r.ParseForm()
		// GitHub accepts both form and JSON body; the provider sends form.
		if got := r.FormValue("client_id"); got != opts.expectClientID {
			t.Errorf("client_id = %q, want %q", got, opts.expectClientID)
		}
		if got := r.FormValue("client_secret"); got != opts.expectClientSecret {
			t.Errorf("client_secret = %q, want %q", got, opts.expectClientSecret)
		}
		if got := r.FormValue("code"); got != opts.expectCode {
			t.Errorf("code = %q, want %q", got, opts.expectCode)
		}
		if got := r.FormValue("code_verifier"); got != opts.expectVerifier {
			t.Errorf("code_verifier = %q, want %q", got, opts.expectVerifier)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"access_token": opts.accessToken,
			"token_type":   "bearer",
			"scope":        "read:user,user:email",
		})
	})

	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer "+opts.accessToken {
			t.Errorf("/user Authorization = %q, want %q", got, "Bearer "+opts.accessToken)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":         opts.userID,
			"login":      opts.login,
			"name":       opts.name,
			"avatar_url": opts.avatarURL,
		})
	})

	mux.HandleFunc("/user/emails", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer "+opts.accessToken {
			t.Errorf("/user/emails Authorization = %q, want %q", got, "Bearer "+opts.accessToken)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(opts.emailsJSON))
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

type mockOpts struct {
	expectClientID     string
	expectClientSecret string
	expectCode         string
	expectVerifier     string
	accessToken        string
	userID             int64
	login              string
	name               string
	avatarURL          string
	emailsJSON         string
}

func TestExchangeCodeParsesTokenResponse(t *testing.T) {
	srv := mockGitHub(t, mockOpts{
		expectClientID:     "cid",
		expectClientSecret: "csec",
		expectCode:         "auth-code-xyz",
		expectVerifier:     "verifier-abc",
		accessToken:        "gho_test1234",
	})
	p := ghprov.New(ghprov.Config{
		ClientID:     "cid",
		ClientSecret: "csec",
		TokenURL:     srv.URL + "/login/oauth/access_token",
		UserURL:      srv.URL + "/user",
		EmailsURL:    srv.URL + "/user/emails",
	})
	tok, err := p.ExchangeCode(context.Background(), "auth-code-xyz", "verifier-abc", "https://r")
	if err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken != "gho_test1234" {
		t.Fatalf("AccessToken = %q", tok.AccessToken)
	}
	if !strings.EqualFold(tok.TokenType, "bearer") {
		t.Fatalf("TokenType = %q", tok.TokenType)
	}
	if tok.Scope != "read:user,user:email" {
		t.Fatalf("Scope = %q", tok.Scope)
	}
}

func TestUserInfoPicksPrimaryVerifiedEmail(t *testing.T) {
	srv := mockGitHub(t, mockOpts{
		accessToken: "gho_pickmail",
		userID:      99,
		login:       "octocat",
		name:        "Mona Lisa",
		avatarURL:   "https://avatars.example.com/u/99",
		emailsJSON: `[
            {"email":"secondary@example.com","primary":false,"verified":true},
            {"email":"unverified@example.com","primary":true,"verified":false},
            {"email":"primary@example.com","primary":true,"verified":true}
        ]`,
	})
	p := ghprov.New(ghprov.Config{
		ClientID:     "cid",
		ClientSecret: "csec",
		TokenURL:     srv.URL + "/login/oauth/access_token",
		UserURL:      srv.URL + "/user",
		EmailsURL:    srv.URL + "/user/emails",
	})
	user, err := p.UserInfo(context.Background(), &theauth.ProviderToken{AccessToken: "gho_pickmail"})
	if err != nil {
		t.Fatal(err)
	}
	if user.ID != "99" {
		t.Fatalf("ID = %q, want %q", user.ID, "99")
	}
	if user.Name != "Mona Lisa" {
		t.Fatalf("Name = %q", user.Name)
	}
	if user.AvatarURL != "https://avatars.example.com/u/99" {
		t.Fatalf("AvatarURL = %q", user.AvatarURL)
	}
	if user.Email != "primary@example.com" {
		t.Fatalf("Email = %q, want primary verified email", user.Email)
	}
	if !user.EmailVerified {
		t.Fatal("EmailVerified should be true when a primary verified email exists")
	}
}

func TestUserInfoNoPrimaryVerifiedEmail(t *testing.T) {
	srv := mockGitHub(t, mockOpts{
		accessToken: "gho_noprimary",
		userID:      7,
		login:       "ghost",
		name:        "Ghost",
		avatarURL:   "https://avatars.example.com/u/7",
		emailsJSON: `[
            {"email":"unverified@example.com","primary":true,"verified":false},
            {"email":"verified-not-primary@example.com","primary":false,"verified":true}
        ]`,
	})
	p := ghprov.New(ghprov.Config{
		ClientID:     "cid",
		ClientSecret: "csec",
		TokenURL:     srv.URL + "/login/oauth/access_token",
		UserURL:      srv.URL + "/user",
		EmailsURL:    srv.URL + "/user/emails",
	})
	user, err := p.UserInfo(context.Background(), &theauth.ProviderToken{AccessToken: "gho_noprimary"})
	if err != nil {
		t.Fatal(err)
	}
	if user.EmailVerified {
		t.Fatal("EmailVerified must be false when there is no primary verified email")
	}
	// We surface SOME email so the find-or-create flow has something to
	// match on; the verified flag is what tells callers whether to trust it.
	if user.Email == "" {
		t.Fatal("Email should fall back to first verified or first available")
	}
}
