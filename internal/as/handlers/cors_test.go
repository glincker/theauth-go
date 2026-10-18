package handlers_test

import (
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	internalas "github.com/glincker/theauth-go/v2/internal/as"
	"github.com/glincker/theauth-go/v2/internal/as/handlers"
	"github.com/glincker/theauth-go/v2/internal/models"
	"github.com/glincker/theauth-go/v2/storage/memory"
	"github.com/go-chi/chi/v5"
)

const corsApp = "https://app.example.com"

func newCORSServer(t *testing.T, cors internalas.CORSConfig) *httptest.Server {
	t.Helper()
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	cfg := internalas.Config{
		Issuer:          "https://auth.example.com",
		Resources:       []models.ProtectedResource{{Identifier: "https://api.example.com"}},
		DisableRotation: true,
		CORS:            cors,
	}
	if err := internalas.Validate(&cfg, key); err != nil {
		t.Fatal(err)
	}
	svc := internalas.New(internalas.Deps{Cfg: cfg, Storage: memory.New(), EncryptionKey: key})
	h := handlers.New(svc, func(*http.Request) (*models.User, bool) { return nil, false }, nil)
	r := chi.NewRouter()
	pass := func(next http.Handler) http.Handler { return next }
	h.Mount(r, pass, nil)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return srv
}

func doCORS(t *testing.T, method, url, origin string, hdr map[string]string, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func vary(h http.Header) string { return strings.Join(h.Values("Vary"), ", ") }

func allGroups() internalas.CORSConfig {
	return internalas.CORSConfig{
		AllowedOrigins: []string{corsApp},
		Discovery:      true, JWKS: true, Register: true, Token: true,
		Introspect: true, Revoke: true, UserInfo: true,
	}
}

func TestCORSPreflightPerGroup(t *testing.T) {
	srv := newCORSServer(t, allGroups())
	tests := []struct {
		name, path, method, wantMethods string
	}{
		{"metadata", "/.well-known/oauth-authorization-server", "GET", "GET"},
		{"openid configuration", "/.well-known/openid-configuration", "GET", "GET"},
		{"protected resource", "/.well-known/oauth-protected-resource", "GET", "GET"},
		{"jwks", "/oauth/jwks", "GET", "GET"},
		{"register", "/oauth/register", "POST", "POST"},
		{"token", "/oauth/token", "POST", "POST"},
		{"introspect", "/oauth/introspect", "POST", "POST"},
		{"revoke", "/oauth/revoke", "POST", "POST"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := doCORS(t, http.MethodOptions, srv.URL+tc.path, corsApp, map[string]string{
				"Access-Control-Request-Method":  tc.method,
				"Access-Control-Request-Headers": "authorization, dpop",
			}, "")
			if resp.StatusCode != http.StatusNoContent {
				t.Fatalf("status %d", resp.StatusCode)
			}
			h := resp.Header
			if got := h.Get("Access-Control-Allow-Origin"); got != corsApp {
				t.Errorf("ACAO %q", got)
			}
			if got := h.Get("Access-Control-Allow-Methods"); got != tc.wantMethods {
				t.Errorf("methods %q want %q", got, tc.wantMethods)
			}
			for _, want := range []string{"Authorization", "Content-Type", "DPoP"} {
				if !strings.Contains(h.Get("Access-Control-Allow-Headers"), want) {
					t.Errorf("allow headers %q lacks %s", h.Get("Access-Control-Allow-Headers"), want)
				}
			}
			if h.Get("Access-Control-Max-Age") != "600" {
				t.Errorf("max age %q", h.Get("Access-Control-Max-Age"))
			}
			if !strings.Contains(vary(h), "Origin") {
				t.Errorf("Vary %q", vary(h))
			}
		})
	}
}

func TestCORSPreflightUserInfo(t *testing.T) {
	cfg := allGroups()
	// userinfo is mounted only when OIDC is on, so check the policy directly.
	p := internalas.NewCORSPolicy(cfg)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodOptions, "/oauth/userinfo", nil)
	req.Header.Set("Origin", corsApp)
	req.Header.Set("Access-Control-Request-Method", "POST")
	p.Preflight(internalas.CORSUserInfo)(rec, req)
	if rec.Code != http.StatusNoContent || rec.Header().Get("Access-Control-Allow-Methods") != "GET, POST" {
		t.Fatalf("code %d methods %q", rec.Code, rec.Header().Get("Access-Control-Allow-Methods"))
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != corsApp {
		t.Fatalf("ACAO %q", rec.Header().Get("Access-Control-Allow-Origin"))
	}
}

func TestCORSPreflightRefusals(t *testing.T) {
	srv := newCORSServer(t, allGroups())
	tests := []struct {
		name, origin, method string
	}{
		{"unlisted origin", "https://evil.example.net", "POST"},
		{"null origin", "null", "POST"},
		{"method the endpoint does not serve", corsApp, "DELETE"},
		{"no origin", "", "POST"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := doCORS(t, http.MethodOptions, srv.URL+"/oauth/token", tc.origin,
				map[string]string{"Access-Control-Request-Method": tc.method}, "")
			if resp.StatusCode != http.StatusNoContent {
				t.Fatalf("status %d", resp.StatusCode)
			}
			for _, k := range []string{"Access-Control-Allow-Origin", "Access-Control-Allow-Methods", "Access-Control-Allow-Credentials"} {
				if v := resp.Header.Get(k); v != "" {
					t.Errorf("%s = %q", k, v)
				}
			}
		})
	}
}

func TestCORSActualResponses(t *testing.T) {
	srv := newCORSServer(t, allGroups())

	t.Run("exposed headers and Vary on a token error", func(t *testing.T) {
		resp := doCORS(t, http.MethodPost, srv.URL+"/oauth/token", corsApp, nil, "grant_type=bogus")
		if resp.StatusCode < 400 {
			t.Fatalf("status %d", resp.StatusCode)
		}
		if resp.Header.Get("Access-Control-Allow-Origin") != corsApp {
			t.Fatalf("ACAO %q", resp.Header.Get("Access-Control-Allow-Origin"))
		}
		exp := resp.Header.Get("Access-Control-Expose-Headers")
		if !strings.Contains(exp, "DPoP-Nonce") || !strings.Contains(exp, "WWW-Authenticate") {
			t.Errorf("expose %q", exp)
		}
		if !strings.Contains(vary(resp.Header), "Origin") {
			t.Errorf("Vary %q", vary(resp.Header))
		}
	})

	t.Run("disallowed origin gets no ACAO but Vary", func(t *testing.T) {
		for _, origin := range []string{"https://evil.example.net", "null", "https://app.example.com.evil.net"} {
			resp := doCORS(t, http.MethodPost, srv.URL+"/oauth/token", origin, nil, "grant_type=bogus")
			if v := resp.Header.Get("Access-Control-Allow-Origin"); v != "" {
				t.Errorf("origin %q reflected as %q", origin, v)
			}
			if resp.Header.Get("Access-Control-Expose-Headers") != "" {
				t.Errorf("origin %q got expose headers", origin)
			}
			if !strings.Contains(vary(resp.Header), "Origin") {
				t.Errorf("origin %q: Vary %q", origin, vary(resp.Header))
			}
		}
	})

	t.Run("discovery and jwks carry ACAO", func(t *testing.T) {
		for _, p := range []string{"/.well-known/oauth-authorization-server", "/oauth/jwks"} {
			resp := doCORS(t, http.MethodGet, srv.URL+p, corsApp, nil, "")
			if resp.StatusCode != http.StatusOK || resp.Header.Get("Access-Control-Allow-Origin") != corsApp {
				t.Errorf("%s: %d ACAO %q", p, resp.StatusCode, resp.Header.Get("Access-Control-Allow-Origin"))
			}
		}
	})

	t.Run("case and trailing slash normalization", func(t *testing.T) {
		s := newCORSServer(t, internalas.CORSConfig{AllowedOrigins: []string{"HTTPS://App.Example.COM/"}, Token: true})
		resp := doCORS(t, http.MethodPost, s.URL+"/oauth/token", "https://app.example.com", nil, "grant_type=bogus")
		if resp.Header.Get("Access-Control-Allow-Origin") != corsApp {
			t.Fatalf("ACAO %q", resp.Header.Get("Access-Control-Allow-Origin"))
		}
		resp = doCORS(t, http.MethodPost, s.URL+"/oauth/token", "https://APP.example.com:443", nil, "grant_type=bogus")
		if resp.Header.Get("Access-Control-Allow-Origin") != corsApp {
			t.Fatalf("default port ACAO %q", resp.Header.Get("Access-Control-Allow-Origin"))
		}
	})

	t.Run("only enabled groups get headers", func(t *testing.T) {
		s := newCORSServer(t, internalas.CORSConfig{AllowedOrigins: []string{corsApp}, Discovery: true})
		resp := doCORS(t, http.MethodPost, s.URL+"/oauth/token", corsApp, nil, "grant_type=bogus")
		if resp.Header.Get("Access-Control-Allow-Origin") != "" || vary(resp.Header) != "" {
			t.Errorf("token got CORS headers: %v", resp.Header)
		}
		resp = doCORS(t, http.MethodOptions, s.URL+"/oauth/token", corsApp, map[string]string{"Access-Control-Request-Method": "POST"}, "")
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("token preflight status %d", resp.StatusCode)
		}
	})

	t.Run("credentials only for an exact origin", func(t *testing.T) {
		cfg := internalas.CORSConfig{AllowedOrigins: []string{corsApp}, Token: true, AllowCredentials: true}
		s := newCORSServer(t, cfg)
		resp := doCORS(t, http.MethodPost, s.URL+"/oauth/token", corsApp, nil, "grant_type=bogus")
		if resp.Header.Get("Access-Control-Allow-Credentials") != "true" {
			t.Errorf("credentials header %q", resp.Header.Get("Access-Control-Allow-Credentials"))
		}
		resp = doCORS(t, http.MethodPost, s.URL+"/oauth/token", "https://other.example.com", nil, "grant_type=bogus")
		if resp.Header.Get("Access-Control-Allow-Credentials") != "" {
			t.Errorf("credentials sent to unlisted origin")
		}
	})
}

func TestCORSWildcardPublicDocumentsOnly(t *testing.T) {
	srv := newCORSServer(t, internalas.CORSConfig{
		PublicOrigins:  []string{"*"},
		AllowedOrigins: []string{corsApp},
		Discovery:      true, JWKS: true, Token: true,
	})
	resp := doCORS(t, http.MethodGet, srv.URL+"/oauth/jwks", "https://anything.example.org", nil, "")
	if resp.Header.Get("Access-Control-Allow-Origin") != "*" {
		t.Errorf("jwks ACAO %q", resp.Header.Get("Access-Control-Allow-Origin"))
	}
	resp = doCORS(t, http.MethodPost, srv.URL+"/oauth/token", "https://anything.example.org", nil, "grant_type=bogus")
	if v := resp.Header.Get("Access-Control-Allow-Origin"); v != "" {
		t.Errorf("token ACAO %q", v)
	}
}

func TestCORSValidation(t *testing.T) {
	tests := []struct {
		name string
		cfg  internalas.CORSConfig
		want error
	}{
		{"wildcard with token", internalas.CORSConfig{AllowedOrigins: []string{"*"}, Token: true}, internalas.ErrCORSWildcardPrivate},
		{"wildcard with register", internalas.CORSConfig{AllowedOrigins: []string{"*"}, Discovery: true, Register: true}, internalas.ErrCORSWildcardPrivate},
		{"wildcard with introspect", internalas.CORSConfig{AllowedOrigins: []string{"*"}, Introspect: true}, internalas.ErrCORSWildcardPrivate},
		{"wildcard with revoke", internalas.CORSConfig{AllowedOrigins: []string{"*"}, Revoke: true}, internalas.ErrCORSWildcardPrivate},
		{"wildcard with userinfo", internalas.CORSConfig{AllowedOrigins: []string{"*"}, UserInfo: true}, internalas.ErrCORSWildcardPrivate},
		{"credentials with wildcard", internalas.CORSConfig{AllowedOrigins: []string{"*"}, Discovery: true, AllowCredentials: true}, internalas.ErrCORSWildcardCredentials},
		{"credentials with public wildcard", internalas.CORSConfig{PublicOrigins: []string{"*"}, Discovery: true, Token: true, AllowedOrigins: []string{corsApp}, AllowCredentials: true}, internalas.ErrCORSWildcardCredentials},
		{"null origin", internalas.CORSConfig{AllowedOrigins: []string{"null"}, Token: true}, internalas.ErrCORSInvalidOrigin},
		{"origin with path", internalas.CORSConfig{AllowedOrigins: []string{"https://a.example.com/x"}, Token: true}, internalas.ErrCORSInvalidOrigin},
		{"origin without scheme", internalas.CORSConfig{AllowedOrigins: []string{"app.example.com"}, Token: true}, internalas.ErrCORSInvalidOrigin},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.cfg
			err := internalas.ValidateCORS(&cfg)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v want %v", err, tc.want)
			}
			if err.Error() == "" {
				t.Fatal("empty error")
			}
		})
	}

	t.Run("wildcard for public documents is valid", func(t *testing.T) {
		cfg := internalas.CORSConfig{AllowedOrigins: []string{"*"}, Discovery: true, JWKS: true}
		if err := internalas.ValidateCORS(&cfg); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("Validate fails fast through the AS config", func(t *testing.T) {
		key := make([]byte, 32)
		cfg := internalas.Config{Issuer: "https://auth.example.com", CORS: internalas.CORSConfig{AllowedOrigins: []string{"*"}, Token: true}}
		if err := internalas.Validate(&cfg, key); !errors.Is(err, internalas.ErrCORSWildcardPrivate) {
			t.Fatalf("got %v", err)
		}
	})
}

func TestCORSZeroConfigUnchanged(t *testing.T) {
	srv := newCORSServer(t, internalas.CORSConfig{})
	for _, p := range []string{"/.well-known/oauth-authorization-server", "/oauth/jwks"} {
		resp := doCORS(t, http.MethodGet, srv.URL+p, corsApp, nil, "")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: %d", p, resp.StatusCode)
		}
		for k := range resp.Header {
			if strings.HasPrefix(k, "Access-Control-") || k == "Vary" {
				t.Errorf("%s: unexpected header %s", p, k)
			}
		}
	}
	resp := doCORS(t, http.MethodPost, srv.URL+"/oauth/token", corsApp, nil, "grant_type=bogus")
	for k := range resp.Header {
		if strings.HasPrefix(k, "Access-Control-") || k == "Vary" {
			t.Errorf("token: unexpected header %s", k)
		}
	}
	resp = doCORS(t, http.MethodOptions, srv.URL+"/oauth/token", corsApp, map[string]string{"Access-Control-Request-Method": "POST"}, "")
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("preflight without config: %d", resp.StatusCode)
	}
}

func TestNormalizeOrigin(t *testing.T) {
	tests := []struct {
		in, want string
		ok       bool
	}{
		{"https://App.Example.com/", "https://app.example.com", true},
		{"http://localhost:3000", "http://localhost:3000", true},
		{"https://a.example.com:443", "https://a.example.com", true},
		{"http://a.example.com:80", "http://a.example.com", true},
		{"https://a.example.com:8443", "https://a.example.com:8443", true},
		{"null", "", false},
		{"", "", false},
		{"ftp://a.example.com", "", false},
		{"https://a.example.com/path", "", false},
		{"https://user@a.example.com", "", false},
		{"https://a.example.com:99999", "", false},
	}
	for _, tc := range tests {
		t.Run(url.PathEscape(tc.in), func(t *testing.T) {
			got, ok := internalas.NormalizeOrigin(tc.in)
			if got != tc.want || ok != tc.ok {
				t.Fatalf("got %q,%v want %q,%v", got, ok, tc.want, tc.ok)
			}
		})
	}
}
