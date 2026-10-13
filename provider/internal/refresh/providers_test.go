package refresh_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/provider/generic"
	ghprov "github.com/glincker/theauth-go/v2/provider/github"
	googprov "github.com/glincker/theauth-go/v2/provider/google"
	msprov "github.com/glincker/theauth-go/v2/provider/microsoft"
	"github.com/glincker/theauth-go/v2/provider/oidc"
)

// refreshEndpoint answers the refresh_token grant, or invalid_grant when the
// presented refresh token is not "good-rt".
func refreshEndpoint(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "application/json")
		if r.Form.Get("grant_type") != "refresh_token" || r.Form.Get("refresh_token") != "good-rt" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "fresh-at", "refresh_token": "rotated-rt", "expires_in": 3600, "token_type": "Bearer",
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestProvidersImplementRefresh(t *testing.T) {
	srv := refreshEndpoint(t)
	gen, err := generic.New(generic.Spec{Name: "gen", AuthURL: srv.URL + "/a", TokenURL: srv.URL, UserURL: srv.URL + "/u",
		Fields: generic.Fields{ID: []string{"id"}}},
		generic.Config{ClientID: "c", ClientSecret: "s"})
	if err != nil {
		t.Fatal(err)
	}
	providers := map[string]theauth.Provider{
		"google":    googprov.New(googprov.Config{ClientID: "c", ClientSecret: "s", TokenURL: srv.URL}),
		"microsoft": msprov.New(msprov.Config{ClientID: "c", ClientSecret: "s", TokenURL: srv.URL}),
		"github":    ghprov.New(ghprov.Config{ClientID: "c", ClientSecret: "s", TokenURL: srv.URL}),
		"generic":   gen,
	}
	for name, p := range providers {
		t.Run(name, func(t *testing.T) {
			rp, ok := p.(theauth.RefreshProvider)
			if !ok {
				t.Fatalf("%s does not implement RefreshProvider", name)
			}
			tok, err := rp.RefreshToken(context.Background(), "good-rt")
			if err != nil {
				t.Fatal(err)
			}
			if tok.AccessToken != "fresh-at" || tok.RefreshToken != "rotated-rt" || tok.ExpiresAt.IsZero() {
				t.Fatalf("token = %+v", tok)
			}
			if _, err := rp.RefreshToken(context.Background(), "stale-rt"); !errors.Is(err, theauth.ErrProviderGrantRevoked) {
				t.Fatalf("stale refresh token: err = %v, want ErrProviderGrantRevoked", err)
			}
		})
	}
}

func TestGoogleOfflineAuthURL(t *testing.T) {
	p := googprov.New(googprov.Config{ClientID: "c", ClientSecret: "s", Offline: true})
	u := p.AuthURL("s", "c", "https://r", nil)
	if !strings.Contains(u, "access_type=offline") || !strings.Contains(u, "prompt=consent") {
		t.Fatalf("offline params missing: %s", u)
	}
	off := googprov.New(googprov.Config{ClientID: "c", ClientSecret: "s"}).AuthURL("s", "c", "https://r", nil)
	if strings.Contains(off, "access_type") {
		t.Fatalf("access_type must be absent by default: %s", off)
	}
}

func TestOIDCImplementsRefresh(t *testing.T) {
	var srv *httptest.Server
	mux := http.NewServeMux()
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": srv.URL, "authorization_endpoint": srv.URL + "/authorize", "token_endpoint": srv.URL + "/token",
			"jwks_uri": srv.URL + "/jwks", "code_challenge_methods_supported": []string{"S256"},
			"token_endpoint_auth_methods_supported": []string{"client_secret_post"},
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("refresh_token") != "good-rt" || r.Form.Get("client_secret") != "s" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		_, _ = w.Write([]byte(`{"access_token":"oidc-at","expires_in":60,"token_type":"Bearer"}`))
	})
	p, err := oidc.New(context.Background(), oidc.Config{Issuer: srv.URL, ClientID: "c", ClientSecret: "s", AllowInsecureHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	rp, ok := p.(theauth.RefreshProvider)
	if !ok {
		t.Fatal("oidc provider does not implement RefreshProvider")
	}
	tok, err := rp.RefreshToken(context.Background(), "good-rt")
	if err != nil || tok.AccessToken != "oidc-at" || tok.RefreshToken != "" {
		t.Fatalf("token = %+v, %v", tok, err)
	}
	if _, err := rp.RefreshToken(context.Background(), "bad"); !errors.Is(err, theauth.ErrProviderGrantRevoked) {
		t.Fatalf("err = %v", err)
	}
}
