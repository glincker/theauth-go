// Command demo runs the official Go MCP SDK client against a theauth-go
// authorization server and prints each HTTP request it makes. Login and
// consent are simulated with a pre-made session, as in the interop tests.
package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
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
	green       = "\x1b[32m"
	yellow      = "\x1b[33m"
	dim         = "\x1b[2m"
	bold        = "\x1b[1m"
	reset       = "\x1b[0m"
)

// swap lets a test server start (so its URL is known) before its handler exists.
type swap struct{ h atomic.Value }

func (s *swap) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.h.Load().(http.Handler).ServeHTTP(w, r)
}

// stepLog prints one line per request the client makes, labelled by RFC.
type stepLog struct {
	next    http.RoundTripper
	n       int
	authed  bool
	stopped bool
}

func (s *stepLog) RoundTrip(r *http.Request) (*http.Response, error) {
	res, err := s.next.RoundTrip(r)
	if err != nil {
		return res, err
	}
	label := ""
	switch {
	case strings.Contains(r.URL.Path, "/.well-known/oauth-protected-resource"):
		label = "discover resource   (RFC 9728)"
	case strings.Contains(r.URL.Path, "/.well-known/oauth-authorization-server"):
		label = "discover auth server (RFC 8414)"
	case r.URL.Path == "/oauth/register":
		label = "register client      (RFC 7591)"
	case r.URL.Path == "/oauth/authorize":
		label = "authorize + PKCE S256 (RFC 7636, 8707)"
	case r.URL.Path == "/oauth/token":
		label = "exchange code for token"
	case r.URL.Path == "/mcp" && res.StatusCode == http.StatusUnauthorized:
		label = "call MCP server, no token: challenged"
	case r.URL.Path == "/mcp" && !s.authed && !s.stopped:
		s.authed = true
		label = "open MCP session with bearer token"
	default:
		return res, nil
	}
	s.n++
	color := green
	if res.StatusCode >= 400 {
		color = yellow
	}
	fmt.Printf("%s%2d%s  %-4s %-40s %s%d%s  %s%s%s\n", bold, s.n, reset, r.Method, r.URL.Path, color, res.StatusCode, reset, dim, label, reset)
	return res, nil
}

func main() {
	slog.SetLogLoggerLevel(slog.LevelError)
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	asSwap, rsSwap := &swap{}, &swap{}
	as := httptest.NewTLSServer(asSwap)
	rs := httptest.NewTLSServer(rsSwap)
	defer as.Close()
	defer rs.Close()
	resource := rs.URL + "/mcp"
	hc := as.Client()
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	stop := &stepLog{next: hc.Transport}
	hc.Transport = stop

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return err
	}
	store := memory.New()
	a, err := theauth.New(theauth.Config{
		Storage:       store,
		BaseURL:       as.URL,
		EncryptionKey: key,
		AuthorizationServer: &theauth.AuthorizationServerConfig{
			Issuer:                         as.URL,
			Resources:                      []theauth.ProtectedResource{{Identifier: resource, Scopes: []string{scopeRead}}},
			DisableRotation:                true,
			AllowAnonymousRegistration:     true,
			RegistrationRateLimitPerMinute: -1,
			RateLimits:                     &theauth.ASRateLimits{PerIPPerMinute: -1, PerClientPerMinute: -1},
		},
	})
	if err != nil {
		return err
	}
	defer a.Close()
	r := chi.NewRouter()
	a.Mount(r)
	asSwap.h.Store(r)

	user, err := store.CreateUser(ctx, theauth.User{ID: ulid.Make(), Email: "demo@example.test", CreatedAt: time.Now()})
	if err != nil {
		return err
	}
	tok, err := crypto.NewToken()
	if err != nil {
		return err
	}
	if _, err := store.CreateSession(ctx, theauth.Session{ID: ulid.Make(), UserID: user.ID, TokenHash: crypto.HashToken(tok), ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		return err
	}

	v := mcpresource.New(resource, mcpresource.WithJWKS(as.URL+"/oauth/jwks"), mcpresource.WithHTTPClient(hc))
	srv := mcp.NewServer(&mcp.Implementation{Name: "demo", Version: "0.0.1"}, nil)
	type in struct{}
	type out struct {
		Subject string `json:"subject"`
		Scope   string `json:"scope"`
	}
	mcp.AddTool(srv, &mcp.Tool{Name: "whoami", Description: "returns the authenticated principal"},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ in) (*mcp.CallToolResult, out, error) {
			p, ok := v.Principal(ctx)
			if !ok {
				return nil, out{}, http.ErrNoCookie
			}
			return nil, out{Subject: p.Subject, Scope: strings.Join(p.Scope, " ")}, nil
		})
	h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, nil)
	mux := http.NewServeMux()
	mux.Handle("/mcp", v.Middleware(h))
	mux.Handle("/.well-known/oauth-protected-resource/mcp", auth.ProtectedResourceMetadataHandler(&oauthex.ProtectedResourceMetadata{
		Resource:               resource,
		AuthorizationServers:   []string{as.URL},
		ScopesSupported:        []string{scopeRead},
		BearerMethodsSupported: []string{"header"},
	}))
	rsSwap.h.Store(mux)

	fetch := func(ctx context.Context, args *auth.AuthorizationArgs) (*auth.AuthorizationResult, error) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, args.URL, nil)
		req.AddCookie(&http.Cookie{Name: cookieName, Value: tok})
		res, err := hc.Do(req)
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
	handler, err := auth.NewAuthorizationCodeHandler(&auth.AuthorizationCodeHandlerConfig{
		DynamicClientRegistrationConfig: &auth.DynamicClientRegistrationConfig{Metadata: &oauthex.ClientRegistrationMetadata{
			RedirectURIs: []string{redirectURL},
			ClientName:   "go-sdk demo",
		}},
		RedirectURL:              redirectURL,
		AuthorizationCodeFetcher: fetch,
		Client:                   hc,
	})
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "%smodelcontextprotocol/go-sdk client -> theauth-go authorization server%s\n\n", bold, reset)
	client := mcp.NewClient(&mcp.Implementation{Name: "go-sdk-client", Version: "0.0.1"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: resource, HTTPClient: hc, OAuthHandler: handler}, nil)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer func() { _ = session.Close() }()

	res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "whoami"})
	if err != nil || res.IsError {
		return fmt.Errorf("call tool: %v", err)
	}
	stop.stopped = true
	sc, _ := res.StructuredContent.(map[string]any)
	fmt.Printf("\n%s✓%s tool whoami returned subject=%v scope=%v\n", green, reset, sc["subject"], sc["scope"])
	return nil
}
