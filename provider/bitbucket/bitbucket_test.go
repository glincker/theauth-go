package bitbucket_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/glincker/theauth-go"
	bbprov "github.com/glincker/theauth-go/provider/bitbucket"
)

func TestNameIsBitbucket(t *testing.T) {
	p := bbprov.New(bbprov.Config{ClientID: "x", ClientSecret: "y"})
	if got := p.Name(); got != "bitbucket" {
		t.Fatalf("Name() = %q, want %q", got, "bitbucket")
	}
}

func TestAuthURLContainsRequiredParams(t *testing.T) {
	p := bbprov.New(bbprov.Config{ClientID: "bb-client", ClientSecret: "shh"})
	got := p.AuthURL("state-xyz", "challenge-123", "https://app.example.com/callback", nil)
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("AuthURL not parseable: %v", err)
	}
	q := u.Query()
	if q.Get("client_id") != "bb-client" {
		t.Fatalf("client_id missing: %s", got)
	}
	if q.Get("code_challenge_method") != "S256" {
		t.Fatalf("code_challenge_method missing: %s", got)
	}
	if q.Get("state") != "state-xyz" {
		t.Fatalf("state missing: %s", got)
	}
}

func mockBitbucket(t *testing.T, accessToken, accountID, displayName, avatarURL, email string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/site/oauth2/access_token", func(w http.ResponseWriter, r *http.Request) {
		// Verify Basic auth is used.
		user, _, ok := r.BasicAuth()
		if !ok || user == "" {
			t.Errorf("expected Basic auth, got none")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  accessToken,
			"token_type":    "bearer",
			"expires_in":    7200,
			"refresh_token": "test-refresh",
		})
	})

	mux.HandleFunc("/2.0/user", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"account_id":   accountID,
			"display_name": displayName,
			"links": map[string]any{
				"avatar": map[string]any{
					"href": avatarURL,
				},
			},
		})
	})

	mux.HandleFunc("/2.0/user/emails", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"values": []map[string]any{
				{
					"email":        email,
					"is_primary":   true,
					"is_confirmed": true,
				},
			},
		})
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestExchangeCodeUsesBasicAuth(t *testing.T) {
	srv := mockBitbucket(t, "bb-access-token", "", "", "", "")
	p := bbprov.New(bbprov.Config{
		ClientID:     "cid",
		ClientSecret: "csec",
		TokenURL:     srv.URL + "/site/oauth2/access_token",
		UserURL:      srv.URL + "/2.0/user",
		EmailURL:     srv.URL + "/2.0/user/emails",
	})
	tok, err := p.ExchangeCode(context.Background(), "code", "verifier", "https://r")
	if err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken != "bb-access-token" {
		t.Fatalf("AccessToken = %q", tok.AccessToken)
	}
}

func TestUserInfoPicksPrimaryEmail(t *testing.T) {
	srv := mockBitbucket(t, "bb-token", "{ABC-123}", "Test User", "https://bitbucket.org/account/testuser/avatar", "user@example.com")
	p := bbprov.New(bbprov.Config{
		ClientID:     "cid",
		ClientSecret: "csec",
		TokenURL:     srv.URL + "/site/oauth2/access_token",
		UserURL:      srv.URL + "/2.0/user",
		EmailURL:     srv.URL + "/2.0/user/emails",
	})
	user, err := p.UserInfo(context.Background(), &theauth.ProviderToken{AccessToken: "bb-token"})
	if err != nil {
		t.Fatal(err)
	}
	if user.ID != "{ABC-123}" {
		t.Fatalf("ID = %q", user.ID)
	}
	if user.Email != "user@example.com" {
		t.Fatalf("Email = %q", user.Email)
	}
	if !user.EmailVerified {
		t.Fatal("EmailVerified should be true for confirmed primary email")
	}
	if user.Name != "Test User" {
		t.Fatalf("Name = %q", user.Name)
	}
}

func TestUserInfoMissingTokenErrors(t *testing.T) {
	p := bbprov.New(bbprov.Config{ClientID: "x", ClientSecret: "y"})
	_, err := p.UserInfo(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil token")
	}
}
