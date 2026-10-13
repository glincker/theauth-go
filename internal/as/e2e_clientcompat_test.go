package as_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/crypto"
	"github.com/glincker/theauth-go/v2/internal/ulid"
)

// e2e_clientcompat_test.go: end-to-end runs of the Config.ClientCompat
// switches against CIMD client metadata shaped like Claude Desktop, Cursor
// and ChatGPT. The JSON under testdata/clientcompat is REPRESENTATIVE of
// what those clients publicly document (loopback redirects with ephemeral
// ports, no resource parameter, vendor scopes, unknown metadata fields). It
// is not captured traffic.

const compatResource = "https://files.example.com/mcp"

// compatFixtureServer serves a fixture file at /clients/<name>.json, replacing
// the {{CLIENT_ID}} placeholder with the document's own URL so the CIMD
// impersonation guard (client_id == fetch URL) holds.
func compatFixtureServer(t *testing.T, fixture string) (clientID string, httpClient *http.Client) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "clientcompat", fixture))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := strings.ReplaceAll(string(raw), "{{CLIENT_ID}}", srv.URL+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	cs := &cimdServer{server: srv}
	return srv.URL + "/clients/" + fixture, cs.trustingClient()
}

func TestClientCompatRecordedShapes(t *testing.T) {
	full := theauth.ClientCompatConfig{
		OptionalResource:  true,
		DropUnknownScopes: true,
		LoopbackAnyPort:   true,
		PathAudience:      true,
	}
	tests := []struct {
		name         string
		fixture      string
		redirectURI  string
		scope        []string
		resource     string
		wantScope    string
		strictErrIs  error
		refreshScope []string
		refreshRes   string
	}{
		{
			name:         "claude desktop, ephemeral v4 loopback port, no resource, claudeai scope",
			fixture:      "claude_desktop.json",
			redirectURI:  "http://127.0.0.1:52817/callback",
			scope:        []string{"files.read", "claudeai"},
			wantScope:    "files.read",
			strictErrIs:  theauth.ErrOAuthInvalidResource,
			refreshScope: []string{"files.read", "claudeai"},
		},
		{
			name:        "claude desktop, ephemeral v6 loopback port",
			fixture:     "claude_desktop.json",
			redirectURI: "http://[::1]:49152/callback",
			scope:       []string{"files.write", "claudeai"},
			wantScope:   "files.write",
			strictErrIs: theauth.ErrOAuthInvalidResource,
		},
		{
			name:        "cursor, different loopback port than registered, offline_access dropped",
			fixture:     "cursor.json",
			redirectURI: "http://127.0.0.1:61000/oauth/callback",
			scope:       []string{"files.read", "offline_access", "profile"},
			wantScope:   "files.read",
			strictErrIs: theauth.ErrOAuthInvalidResource,
		},
		{
			name:         "chatgpt, fixed https callback, sub-path resource, openid dropped",
			fixture:      "chatgpt.json",
			redirectURI:  "https://chatgpt.com/connector_platform_oauth_redirect",
			scope:        []string{"files.read", "openid"},
			resource:     compatResource + "/sse",
			wantScope:    "files.read",
			strictErrIs:  theauth.ErrOAuthInvalidResource,
			refreshScope: []string{"files.read", "openid"},
			refreshRes:   compatResource + "/sse",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clientID, httpClient := compatFixtureServer(t, tc.fixture)
			withCIMD := func(c *theauth.AuthorizationServerConfig) {
				c.CIMD = &theauth.CIMDConfig{TrustPolicy: theauth.AllowAnyHTTPS(), HTTPClient: httpClient, CacheTTL: time.Minute}
			}
			ctx := context.Background()
			verifier, _ := crypto.NewCodeVerifier()
			authReq := theauth.AuthorizeRequest{
				ClientID:            clientID,
				RedirectURI:         tc.redirectURI,
				ResponseType:        "code",
				Scope:               tc.scope,
				State:               "st",
				CodeChallenge:       crypto.CodeChallenge(verifier),
				CodeChallengeMethod: "S256",
				Resource:            tc.resource,
			}
			user := theauth.User{ID: ulid.New(), Email: "alice@example.com"}

			// Default (strict) configuration rejects the request.
			strictAS, strictStore := newASInstance(t, withCIMD)
			if _, err := strictStore.CreateUser(ctx, user); err != nil {
				t.Fatalf("create user: %v", err)
			}
			if _, err := strictAS.StartAuthorize(ctx, authReq, &user); err == nil || !errors.Is(err, tc.strictErrIs) {
				t.Fatalf("strict StartAuthorize err = %v, want %v", err, tc.strictErrIs)
			}

			// Compat configuration completes the full flow.
			a, store := newASInstance(t, withCIMD, func(c *theauth.AuthorizationServerConfig) { c.ClientCompat = full })
			if _, err := store.CreateUser(ctx, user); err != nil {
				t.Fatalf("create user: %v", err)
			}
			res, err := a.StartAuthorize(ctx, authReq, &user)
			if err != nil {
				t.Fatalf("StartAuthorize: %v", err)
			}
			tok, err := a.ExchangeAuthorizationCode(ctx, theauth.TokenRequest{
				GrantType:    theauth.GrantTypeAuthorizationCode,
				ClientID:     clientID,
				Code:         codeFromRedirect(t, res.RedirectURL),
				CodeVerifier: verifier,
				RedirectURI:  tc.redirectURI,
			})
			if err != nil {
				t.Fatalf("ExchangeAuthorizationCode: %v", err)
			}
			if tok.Scope != tc.wantScope {
				t.Errorf("token response scope = %q, want %q", tok.Scope, tc.wantScope)
			}
			claims := decodeJWTPayload(t, tok.AccessToken)
			if claims["aud"] != compatResource {
				t.Errorf("aud = %v, want canonical %q", claims["aud"], compatResource)
			}
			if claims["scope"] != tc.wantScope {
				t.Errorf("scope claim = %v, want %q", claims["scope"], tc.wantScope)
			}

			if tc.refreshScope == nil {
				return
			}
			rt, err := a.RefreshAccessToken(ctx, theauth.TokenRequest{
				GrantType:    theauth.GrantTypeRefreshToken,
				ClientID:     clientID,
				RefreshToken: tok.RefreshToken,
				Scope:        tc.refreshScope,
				Resource:     tc.refreshRes,
			})
			if err != nil {
				t.Fatalf("RefreshAccessToken: %v", err)
			}
			if rt.Scope != tc.wantScope {
				t.Errorf("refresh scope = %q, want %q", rt.Scope, tc.wantScope)
			}
			if got := decodeJWTPayload(t, rt.AccessToken)["aud"]; got != compatResource {
				t.Errorf("refresh aud = %v, want %q", got, compatResource)
			}
		})
	}
}

// TestClientCompatDefaultsStayStrict pins each switch individually: turning
// one on must not relax the others.
func TestClientCompatDefaultsStayStrict(t *testing.T) {
	clientID, httpClient := compatFixtureServer(t, "claude_desktop.json")
	ctx := context.Background()
	verifier, _ := crypto.NewCodeVerifier()
	user := theauth.User{ID: ulid.New(), Email: "bob@example.com"}
	base := theauth.AuthorizeRequest{
		ClientID:            clientID,
		RedirectURI:         "http://127.0.0.1/callback",
		ResponseType:        "code",
		Scope:               []string{"files.read"},
		CodeChallenge:       crypto.CodeChallenge(verifier),
		CodeChallengeMethod: "S256",
		Resource:            compatResource,
	}
	tests := []struct {
		name   string
		compat theauth.ClientCompatConfig
		mut    func(*theauth.AuthorizeRequest)
		want   error
	}{
		{"unknown scope with only resource flags", theauth.ClientCompatConfig{OptionalResource: true, PathAudience: true, LoopbackAnyPort: true},
			func(r *theauth.AuthorizeRequest) { r.Scope = []string{"files.read", "claudeai"} }, theauth.ErrOAuthInvalidScope},
		{"missing resource with only scope flag", theauth.ClientCompatConfig{DropUnknownScopes: true, PathAudience: true, LoopbackAnyPort: true},
			func(r *theauth.AuthorizeRequest) { r.Resource = "" }, theauth.ErrOAuthInvalidResource},
		{"sub path resource with only optional flag", theauth.ClientCompatConfig{OptionalResource: true, DropUnknownScopes: true, LoopbackAnyPort: true},
			func(r *theauth.AuthorizeRequest) { r.Resource = compatResource + "/sse" }, theauth.ErrOAuthInvalidResource},
		{"ephemeral port with only non-loopback flags", theauth.ClientCompatConfig{OptionalResource: true, DropUnknownScopes: true, PathAudience: true},
			func(r *theauth.AuthorizeRequest) { r.RedirectURI = "http://127.0.0.1:5000/callback" }, theauth.ErrOAuthInvalidRequest},
		{"none left after drop", theauth.ClientCompatConfig{DropUnknownScopes: true},
			func(r *theauth.AuthorizeRequest) { r.Scope = []string{"claudeai"} }, theauth.ErrOAuthInvalidScope},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a, store := newASInstance(t, func(c *theauth.AuthorizationServerConfig) {
				c.CIMD = &theauth.CIMDConfig{TrustPolicy: theauth.AllowAnyHTTPS(), HTTPClient: httpClient, CacheTTL: time.Minute}
				c.ClientCompat = tc.compat
			})
			if _, err := store.CreateUser(ctx, user); err != nil {
				t.Fatalf("create user: %v", err)
			}
			req := base
			tc.mut(&req)
			if _, err := a.StartAuthorize(ctx, req, &user); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestClientCompatPARAndDCRLoopback runs the same switches through PAR and a
// DCR-registered loopback client, then redeems the code at the token
// endpoint with a different ephemeral port than the one registered.
func TestClientCompatPARAndDCRLoopback(t *testing.T) {
	form := func(clientID string, verifier string) url.Values {
		return url.Values{
			"response_type":         {"code"},
			"client_id":             {clientID},
			"redirect_uri":          {"http://127.0.0.1:50123/cb"},
			"scope":                 {"read claudeai"},
			"code_challenge":        {crypto.CodeChallenge(verifier)},
			"code_challenge_method": {"S256"},
		}
	}
	const registered = `{"redirect_uris":["http://127.0.0.1/cb"]}`
	verifier, _ := crypto.NewCodeVerifier()

	t.Run("strict rejects", func(t *testing.T) {
		_, srv, _, _ := newPARASHarness(t)
		client := registerClientWithBody(t, srv, registered)
		if body, status := postPAR(t, srv, client.ClientID, client.ClientSecret, form(client.ClientID, verifier)); status == http.StatusCreated {
			t.Fatalf("strict PAR must reject, got 201 %v", body)
		}
	})

	t.Run("compat accepts and redeems", func(t *testing.T) {
		a, srv, _, rawToken := newPARASHarness(t, func(c *theauth.AuthorizationServerConfig) {
			c.ClientCompat = theauth.ClientCompatConfig{OptionalResource: true, DropUnknownScopes: true, LoopbackAnyPort: true}
		})
		client := registerClientWithBody(t, srv, registered)
		body, status := postPAR(t, srv, client.ClientID, client.ClientSecret, form(client.ClientID, verifier))
		if status != http.StatusCreated {
			t.Fatalf("PAR: status %d body=%v", status, body)
		}
		requestURI, _ := body["request_uri"].(string)
		code, status := authorizeWithRequestURI(t, srv, rawToken, client.ClientID, requestURI)
		if status != http.StatusFound || code == "" {
			t.Fatalf("authorize: status %d code %q", status, code)
		}
		tok, err := a.ExchangeAuthorizationCode(context.Background(), theauth.TokenRequest{
			GrantType:    theauth.GrantTypeAuthorizationCode,
			ClientID:     client.ClientID,
			ClientSecret: client.ClientSecret,
			Code:         code,
			CodeVerifier: verifier,
			// Same loopback URI, different ephemeral port than at /authorize.
			RedirectURI: "http://127.0.0.1:50999/cb",
		})
		if err != nil {
			t.Fatalf("ExchangeAuthorizationCode: %v", err)
		}
		if tok.Scope != "read" {
			t.Errorf("scope = %q, want read", tok.Scope)
		}
		if got := decodeJWTPayload(t, tok.AccessToken)["aud"]; got != "https://api.example.com" {
			t.Errorf("aud = %v", got)
		}
	})
}
