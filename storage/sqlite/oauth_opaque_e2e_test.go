package sqlite_test

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/glincker/theauth-go/mcpresource"
	sqlitestore "github.com/glincker/theauth-go/storage/sqlite"
	"github.com/glincker/theauth-go/v2"
	"github.com/go-chi/chi/v5"
)

// bootOpaqueOAuth boots the same AS as bootOAuth with the token policy on, so
// clients may ask for opaque access tokens (access_token_format opaque).
func bootOpaqueOAuth(t *testing.T) *oaEnv {
	t.Helper()
	path := filepath.Join(t.TempDir(), "oauth-opaque.db")
	db, err := sql.Open("sqlite", "file:"+path+pragmas)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("ping: %v", err)
	}
	if err := sqlitestore.Migrate(t.Context(), db); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	store, err := sqlitestore.New(db)
	if err != nil {
		t.Fatalf("New store: %v", err)
	}
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	clock := &oaClock{t: time.Now()}
	a, err := theauth.New(theauth.Config{
		Storage:       store,
		BaseURL:       oaIssuer,
		EncryptionKey: key,
		AuthorizationServer: &theauth.AuthorizationServerConfig{
			Issuer: oaIssuer,
			Resources: []theauth.ProtectedResource{{
				Identifier: oaResource,
				Scopes:     []string{oaScopeRead, oaScopeWrit},
			}},
			DisableRotation:                true,
			AllowAnonymousRegistration:     true,
			RegistrationRateLimitPerMinute: -1,
			RegistrationTokens:             []string{oaIAT},
			AccessTokenRevocation:          true,
			SubjectActiveCacheTTL:          -1,
			IntrospectionCacheTTL:          time.Second,
			Clock:                          clock,
			RateLimits:                     &theauth.ASRateLimits{PerIPPerMinute: -1, PerClientPerMinute: -1},
			TokenPolicy:                    &theauth.TokenPolicyConfig{},
		},
	})
	if err != nil {
		t.Fatalf("theauth.New with the token policy: %v", err)
	}
	r := chi.NewRouter()
	a.Mount(r)
	srv := httptest.NewServer(r)
	e := &oaEnv{t: t, path: path, key: key, clock: clock, dev: &oaDevice{}, db: db, store: store, a: a, srv: srv}
	e.hc = &http.Client{
		Timeout:       5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	t.Cleanup(e.shutdown)
	return e
}

// TestOpaqueTokenMCPResourceE2E runs authorization code + PKCE for a client
// registered with access_token_format opaque, validates the reference token
// through the mcpresource middleware (WithOpaqueTokens) and proves revocation
// at /oauth/revoke is seen once the resource server cache window passes.
func TestOpaqueTokenMCPResourceE2E(t *testing.T) {
	e := bootOpaqueOAuth(t)
	user, cookie := e.signIn("opaque-rs@levelrail.test")
	rsID, rsSecret := e.registerConfidential("levelrail-mcp-rs", []string{"authorization_code"})

	code, out := e.register(oaJSON{
		"client_name":                "Opaque client (e2e)",
		"redirect_uris":              []string{oaRedirect},
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none",
		"access_token_format":        "opaque",
	}, oaIAT) // token policy metadata needs an authenticated registration
	if code != http.StatusCreated || out.str("client_id") == "" {
		t.Fatalf("opaque DCR: %d %v", code, out)
	}
	opaqueClient := out.str("client_id")
	jwtClient := e.registerNative()

	v := mcpresource.New(oaResource,
		mcpresource.WithJWKS(e.srv.URL+"/oauth/jwks"),
		mcpresource.WithIntrospection(e.srv.URL+"/oauth/introspect", rsID, rsSecret),
		mcpresource.WithOpaqueTokens(),
		mcpresource.WithCacheTTL(20*time.Millisecond),
	)
	if len(v.Diagnostics()) != 1 || v.Diagnostics()[0].Code != "dual-verification" {
		t.Fatalf("Diagnostics = %+v", v.Diagnostics())
	}
	mux := http.NewServeMux()
	mux.Handle("/mcp", v.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, _ := v.Principal(r.Context())
		_ = json.NewEncoder(w).Encode(map[string]any{
			"sub": p.Subject, "scope": p.Scope, "aud": p.Audience, "client": p.ClientID,
		})
	})))
	mux.Handle("/write", v.Middleware(v.RequireScope(oaScopeWrit)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))))
	rs := httptest.NewServer(mux)
	t.Cleanup(rs.Close)
	call := func(path, token string) (int, http.Header, map[string]any) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, rs.URL+path, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		res, err := e.hc.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = res.Body.Close() }()
		var body map[string]any
		_ = json.NewDecoder(res.Body).Decode(&body)
		return res.StatusCode, res.Header, body
	}
	wantMeta := "resource_metadata=\"https://mcp.levelrail.test/.well-known/oauth-protected-resource/mcp\""

	tok := e.tokensFor(opaqueClient, cookie)
	at := tok.str("access_token")
	if at == "" || strings.Count(at, ".") != 0 {
		t.Fatalf("access token %q is not opaque", at)
	}

	t.Run("ValidOpaqueTokenAndPrincipal", func(t *testing.T) {
		status, _, body := call("/mcp", at)
		if status != http.StatusOK {
			t.Fatalf("status %d body %v", status, body)
		}
		if body["sub"] != user.ID.String() || body["aud"] != oaResource || body["client"] != opaqueClient {
			t.Fatalf("principal = %v", body)
		}
		scopes, _ := body["scope"].([]any)
		if len(scopes) != 1 || scopes[0] != oaScopeRead {
			t.Fatalf("scope = %v", body["scope"])
		}
	})

	t.Run("InsufficientScope", func(t *testing.T) {
		status, _, body := call("/write", at)
		if status != http.StatusForbidden || body["error"] != "insufficient_scope" {
			t.Fatalf("got %d %v", status, body)
		}
	})

	t.Run("JWTClientStillWorks", func(t *testing.T) {
		jt := e.tokensFor(jwtClient, cookie).str("access_token")
		if strings.Count(jt, ".") != 2 {
			t.Fatalf("expected a JWT, got %q", jt)
		}
		if status, _, body := call("/mcp", jt); status != http.StatusOK {
			t.Fatalf("JWT through the opaque aware validator: %d %v", status, body)
		}
	})

	t.Run("UnknownOpaqueTokenRejected", func(t *testing.T) {
		status, hdr, body := call("/mcp", "not-a-token-the-as-ever-issued")
		if status != http.StatusUnauthorized || body["error"] != "invalid_token" {
			t.Fatalf("got %d %v", status, body)
		}
		if !strings.Contains(hdr.Get("WWW-Authenticate"), wantMeta) {
			t.Fatalf("WWW-Authenticate = %q", hdr.Get("WWW-Authenticate"))
		}
	})

	t.Run("WrongAudience", func(t *testing.T) {
		other := mcpresource.New("https://other.levelrail.test/mcp",
			mcpresource.WithIntrospection(e.srv.URL+"/oauth/introspect", rsID, rsSecret),
			mcpresource.WithOpaqueTokens())
		h := other.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
		req := httptest.NewRequest(http.MethodGet, "https://other.levelrail.test/mcp", nil)
		req.Header.Set("Authorization", "Bearer "+at)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("token for %s accepted by another resource: %d", oaResource, rec.Code)
		}
	})

	t.Run("RevokedTokenRejectedAfterCacheWindow", func(t *testing.T) {
		if status, _, _ := call("/mcp", at); status != http.StatusOK {
			t.Fatalf("before revoke: %d", status)
		}
		status, res := e.postForm("/oauth/revoke", url.Values{
			"token": {at}, "token_type_hint": {"access_token"}, "client_id": {opaqueClient},
		}, "", "")
		if status != http.StatusOK {
			t.Fatalf("revoke: %d %v", status, res)
		}
		if active(e.introspect(rsID, rsSecret, at)) {
			t.Fatal("AS still reports the revoked opaque token active")
		}
		// The resource server honours the AS Cache-Control max-age (1s) over
		// WithCacheTTL, so the cached "active" answer lives that long.
		time.Sleep(1200 * time.Millisecond)
		status, hdr, body := call("/mcp", at)
		if status != http.StatusUnauthorized || body["error"] != "invalid_token" {
			t.Fatalf("after revoke: %d %v, want 401 invalid_token", status, body)
		}
		if !strings.Contains(hdr.Get("WWW-Authenticate"), wantMeta) {
			t.Fatalf("WWW-Authenticate = %q", hdr.Get("WWW-Authenticate"))
		}
	})
}
