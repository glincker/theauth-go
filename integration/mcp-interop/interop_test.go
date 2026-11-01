package interop_test

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glincker/theauth-go/mcpresource"
	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/crypto"
	"github.com/glincker/theauth-go/v2/storage/memory"
	"github.com/go-chi/chi/v5"
	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
	"github.com/oklog/ulid/v2"
)

const (
	redirectURL = "http://127.0.0.1:8976/callback"
	scopeRead   = "files.read"
	cookieName  = "theauth_session"
)

// swap lets an httptest server start (so its URL is known) before its handler exists.
type swap struct{ h atomic.Value }

func (s *swap) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.h.Load().(http.Handler).ServeHTTP(w, r)
}

type env struct {
	as, rs   *httptest.Server
	resource string
	client   *http.Client
	cookie   *http.Cookie
	userID   string
}

func boot(t *testing.T) *env {
	t.Helper()
	asSwap, rsSwap := &swap{}, &swap{}
	as := httptest.NewTLSServer(asSwap)
	rs := httptest.NewTLSServer(rsSwap)
	t.Cleanup(as.Close)
	t.Cleanup(rs.Close)
	e := &env{as: as, rs: rs, resource: rs.URL + "/mcp", client: as.Client()}
	// The test servers share one certificate, so one client trusts both.
	e.client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	store := memory.New()
	a, err := theauth.New(theauth.Config{
		Storage:       store,
		BaseURL:       as.URL,
		EncryptionKey: key,
		AuthorizationServer: &theauth.AuthorizationServerConfig{
			Issuer:                         as.URL,
			Resources:                      []theauth.ProtectedResource{{Identifier: e.resource, Scopes: []string{scopeRead}}},
			DisableRotation:                true,
			AllowAnonymousRegistration:     true,
			RegistrationRateLimitPerMinute: -1,
			RateLimits:                     &theauth.ASRateLimits{PerIPPerMinute: -1, PerClientPerMinute: -1},
		},
	})
	if err != nil {
		t.Fatalf("theauth.New: %v", err)
	}
	t.Cleanup(a.Close)
	r := chi.NewRouter()
	a.Mount(r)
	asSwap.h.Store(r)

	// A signed-in browser session stands in for the login page.
	ctx := context.Background()
	u, err := store.CreateUser(ctx, theauth.User{ID: ulid.Make(), Email: "interop@example.test", CreatedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := crypto.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateSession(ctx, theauth.Session{ID: ulid.Make(), UserID: u.ID, TokenHash: crypto.HashToken(tok), ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	e.cookie = &http.Cookie{Name: cookieName, Value: tok}
	e.userID = u.ID.String()

	// The MCP server: a go-sdk server behind the theauth mcpresource validator.
	v := mcpresource.New(e.resource,
		mcpresource.WithJWKS(as.URL+"/oauth/jwks"),
		mcpresource.WithHTTPClient(e.client),
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "interop", Version: "0.0.1"}, nil)
	type in struct{}
	type out struct {
		Subject string `json:"subject"`
		Scope   string `json:"scope"`
	}
	mcp.AddTool(srv, &mcp.Tool{Name: "whoami", Description: "returns the authenticated principal"},
		func(ctx context.Context, req *mcp.CallToolRequest, _ in) (*mcp.CallToolResult, out, error) {
			p, ok := v.Principal(ctx)
			if !ok {
				return nil, out{}, http.ErrNoCookie
			}
			return nil, out{Subject: p.Subject, Scope: strings.Join(p.Scope, " ")}, nil
		})
	h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, nil)
	mux := http.NewServeMux()
	// The validator's principal rides on the request context, which the handler passes to tools.
	mux.Handle("/mcp", v.Middleware(h))
	mux.Handle("/.well-known/oauth-protected-resource/mcp", auth.ProtectedResourceMetadataHandler(&oauthex.ProtectedResourceMetadata{
		Resource:               e.resource,
		AuthorizationServers:   []string{as.URL},
		ScopesSupported:        []string{scopeRead},
		BearerMethodsSupported: []string{"header"},
	}))
	rsSwap.h.Store(mux)
	return e
}

// fetcher plays the browser: it hits the authorize URL with the session cookie and reads the redirect.
func (e *env) fetcher(seen *[]string) auth.AuthorizationCodeFetcher {
	return func(ctx context.Context, args *auth.AuthorizationArgs) (*auth.AuthorizationResult, error) {
		*seen = append(*seen, args.URL)
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, args.URL, nil)
		req.AddCookie(e.cookie)
		res, err := e.client.Do(req)
		if err != nil {
			return nil, err
		}
		_ = res.Body.Close()
		loc, err := url.Parse(res.Header.Get("Location"))
		if err != nil || res.StatusCode != http.StatusFound {
			return nil, http.ErrNotSupported
		}
		q := loc.Query()
		return &auth.AuthorizationResult{Code: q.Get("code"), State: q.Get("state"), Iss: q.Get("iss")}, nil
	}
}

// TestDiscoveryDocuments checks the documents the SDK client discovers from before it authorizes.
func TestDiscoveryDocuments(t *testing.T) {
	e := boot(t)
	tests := []struct {
		name string
		url  string
		want map[string]string
	}{
		{"RFC 9728 protected resource", e.rs.URL + "/.well-known/oauth-protected-resource/mcp", map[string]string{"resource": e.resource}},
		{"RFC 8414 authorization server", e.as.URL + "/.well-known/oauth-authorization-server", map[string]string{
			"issuer": e.as.URL, "authorization_endpoint": e.as.URL + "/oauth/authorize", "token_endpoint": e.as.URL + "/oauth/token",
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res, err := e.client.Get(tc.url)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = res.Body.Close() }()
			var doc map[string]any
			if err := json.NewDecoder(res.Body).Decode(&doc); err != nil || res.StatusCode != 200 {
				t.Fatalf("status %d err %v", res.StatusCode, err)
			}
			for k, v := range tc.want {
				if doc[k] != v {
					t.Fatalf("%s = %v, want %s", k, doc[k], v)
				}
			}
		})
	}
	t.Run("AS advertises S256 only", func(t *testing.T) {
		res, err := e.client.Get(e.as.URL + "/.well-known/oauth-authorization-server")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = res.Body.Close() }()
		var doc struct {
			Methods []string `json:"code_challenge_methods_supported"`
		}
		_ = json.NewDecoder(res.Body).Decode(&doc)
		if len(doc.Methods) != 1 || doc.Methods[0] != "S256" {
			t.Fatalf("code_challenge_methods_supported = %v", doc.Methods)
		}
	})
}

// TestUnauthenticatedChallenge checks the 401 the SDK client reacts to carries the RFC 9728 pointer.
func TestUnauthenticatedChallenge(t *testing.T) {
	e := boot(t)
	res, err := e.client.Post(e.resource, "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	wa := res.Header.Get("WWW-Authenticate")
	want := `resource_metadata="` + e.rs.URL + `/.well-known/oauth-protected-resource/mcp"`
	if res.StatusCode != http.StatusUnauthorized || !strings.Contains(wa, want) {
		t.Fatalf("status %d WWW-Authenticate %q, want %s", res.StatusCode, wa, want)
	}
}

// TestSDKClientFullFlow lets the official SDK client discover, register, run PKCE and call a tool.
func TestSDKClientFullFlow(t *testing.T) {
	e := boot(t)
	var authURLs []string
	handler, err := auth.NewAuthorizationCodeHandler(&auth.AuthorizationCodeHandlerConfig{
		DynamicClientRegistrationConfig: &auth.DynamicClientRegistrationConfig{Metadata: &oauthex.ClientRegistrationMetadata{
			RedirectURIs: []string{redirectURL},
			ClientName:   "go-sdk interop",
		}},
		RedirectURL:              redirectURL,
		AuthorizationCodeFetcher: e.fetcher(&authURLs),
		Client:                   e.client,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client := mcp.NewClient(&mcp.Implementation{Name: "go-sdk-client", Version: "0.0.1"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: e.resource, HTTPClient: e.client, OAuthHandler: handler}, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = session.Close() }()

	if len(authURLs) != 1 {
		t.Fatalf("want exactly one authorization round trip, got %d", len(authURLs))
	}
	u, _ := url.Parse(authURLs[0])
	q := u.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" || q.Get("resource") != e.resource {
		t.Fatalf("authorize request missing PKCE S256 or RFC 8707 resource: %v", q)
	}

	res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "whoami"})
	if err != nil || res.IsError {
		t.Fatalf("call tool: %v %+v", err, res)
	}
	sc, _ := res.StructuredContent.(map[string]any)
	if sc["subject"] != e.userID || sc["scope"] != scopeRead {
		t.Fatalf("principal = %v, want subject %s scope %s", sc, e.userID, scopeRead)
	}
}
