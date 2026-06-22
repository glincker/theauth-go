package as_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/crypto"
	"github.com/glincker/theauth-go/internal/cimd"
	"github.com/glincker/theauth-go/internal/ulid"
)

// e2e_cimd_test.go: end-to-end coverage for CIMD-published clients
// hitting the OAuth 2.1 authorize + token endpoints. The MCP
// authorization spec 2025-11-25 makes CIMD the preferred client
// identification mechanism; this test asserts the full flow lands a
// working access token without any DCR step.

// cimdServer is a tiny test fixture: an httptest TLS server that
// publishes one CIMD document, plus an http.Client wired to trust the
// server's self-signed cert.
type cimdServer struct {
	server *httptest.Server
	mu     sync.Mutex
	doc    cimd.Document
}

func newCIMDServer(t *testing.T) *cimdServer {
	t.Helper()
	cs := &cimdServer{}
	cs.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cs.mu.Lock()
		doc := cs.doc
		cs.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(doc)
	}))
	t.Cleanup(cs.server.Close)
	return cs
}

func (cs *cimdServer) URL() string { return cs.server.URL + "/client" }

func (cs *cimdServer) publish(doc cimd.Document) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.doc = doc
}

func (cs *cimdServer) trustingClient() *http.Client {
	return &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
	}
}

func TestCIMDAuthCodeFlowE2E(t *testing.T) {
	cs := newCIMDServer(t)
	a, store := newASInstance(t, func(c *theauth.AuthorizationServerConfig) {
		c.CIMD = &theauth.CIMDConfig{
			TrustPolicy: theauth.AllowAnyHTTPS(),
			HTTPClient:  cs.trustingClient(),
			CacheTTL:    time.Minute,
		}
	})
	cs.publish(cimd.Document{
		ClientID:                cs.URL(),
		ClientName:              "MCP Client",
		RedirectURIs:            []string{"https://app.example.com/cb"},
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none",
		Scope:                   "files.read",
	})
	ctx := context.Background()
	user := theauth.User{ID: ulid.New(), Email: "alice@example.com"}
	if _, err := store.CreateUser(ctx, user); err != nil {
		t.Fatalf("create user: %v", err)
	}
	verifier, _ := crypto.NewCodeVerifier()
	res, err := a.StartAuthorize(ctx, theauth.AuthorizeRequest{
		ClientID:            cs.URL(),
		RedirectURI:         "https://app.example.com/cb",
		ResponseType:        "code",
		Scope:               []string{"files.read"},
		State:               "abc",
		CodeChallenge:       crypto.CodeChallenge(verifier),
		CodeChallengeMethod: "S256",
		Resource:            "https://files.example.com/mcp",
	}, &user)
	if err != nil {
		t.Fatalf("StartAuthorize: %v", err)
	}
	code := codeFromRedirect(t, res.RedirectURL)

	tok, err := a.ExchangeAuthorizationCode(ctx, theauth.TokenRequest{
		GrantType:    theauth.GrantTypeAuthorizationCode,
		ClientID:     cs.URL(),
		Code:         code,
		CodeVerifier: verifier,
		RedirectURI:  "https://app.example.com/cb",
	})
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode: %v", err)
	}
	if tok.AccessToken == "" || tok.RefreshToken == "" {
		t.Fatalf("empty token response: %+v", tok)
	}
}

func TestCIMDPolicyDeniedReturnsInvalidClient(t *testing.T) {
	cs := newCIMDServer(t)
	cs.publish(cimd.Document{
		ClientID:     cs.URL(),
		RedirectURIs: []string{"https://app.example.com/cb"},
	})
	a, _ := newASInstance(t, func(c *theauth.AuthorizationServerConfig) {
		// Trust a host that does not match the test server: every CIMD
		// resolution must fail closed.
		c.CIMD = &theauth.CIMDConfig{
			TrustPolicy: theauth.AllowHTTPSHost("trusted.example"),
			HTTPClient:  cs.trustingClient(),
		}
	})
	verifier, _ := crypto.NewCodeVerifier()
	_, err := a.StartAuthorize(context.Background(), theauth.AuthorizeRequest{
		ClientID:            cs.URL(),
		RedirectURI:         "https://app.example.com/cb",
		ResponseType:        "code",
		Scope:               []string{"files.read"},
		CodeChallenge:       crypto.CodeChallenge(verifier),
		CodeChallengeMethod: "S256",
		Resource:            "https://files.example.com/mcp",
	}, &theauth.User{ID: ulid.New(), Email: "alice@example.com"})
	if err == nil {
		t.Fatal("expected error for policy-denied CIMD URL")
	}
	// Root error mapping converts internal cimd errors into
	// invalid_client at the OAuth wire; we assert the public sentinel.
	if !errors.Is(err, theauth.ErrOAuthInvalidClient) {
		t.Fatalf("want ErrOAuthInvalidClient, got %v", err)
	}
}

func TestCIMDDisabledRejectsHTTPSClientID(t *testing.T) {
	// CIMD not configured: an https-shaped client_id MUST return
	// invalid_client. Falling through to storage would be a downgrade
	// attack vector.
	a, _ := newASInstance(t) // no CIMD wired
	verifier, _ := crypto.NewCodeVerifier()
	_, err := a.StartAuthorize(context.Background(), theauth.AuthorizeRequest{
		ClientID:            "https://anywhere.example/client",
		RedirectURI:         "https://app.example.com/cb",
		ResponseType:        "code",
		Scope:               []string{"files.read"},
		CodeChallenge:       crypto.CodeChallenge(verifier),
		CodeChallengeMethod: "S256",
		Resource:            "https://files.example.com/mcp",
	}, &theauth.User{ID: ulid.New(), Email: "alice@example.com"})
	if !errors.Is(err, theauth.ErrOAuthInvalidClient) {
		t.Fatalf("want ErrOAuthInvalidClient, got %v", err)
	}
}

func TestCIMDDefaultPolicyIsDenyAll(t *testing.T) {
	cs := newCIMDServer(t)
	cs.publish(cimd.Document{
		ClientID:     cs.URL(),
		RedirectURIs: []string{"https://app.example.com/cb"},
	})
	a, _ := newASInstance(t, func(c *theauth.AuthorizationServerConfig) {
		// CIMD configured but TrustPolicy not specified: must default
		// to DenyAll (fail-closed).
		c.CIMD = &theauth.CIMDConfig{HTTPClient: cs.trustingClient()}
	})
	verifier, _ := crypto.NewCodeVerifier()
	_, err := a.StartAuthorize(context.Background(), theauth.AuthorizeRequest{
		ClientID:            cs.URL(),
		RedirectURI:         "https://app.example.com/cb",
		ResponseType:        "code",
		Scope:               []string{"files.read"},
		CodeChallenge:       crypto.CodeChallenge(verifier),
		CodeChallengeMethod: "S256",
		Resource:            "https://files.example.com/mcp",
	}, &theauth.User{ID: ulid.New(), Email: "alice@example.com"})
	if !errors.Is(err, theauth.ErrOAuthInvalidClient) {
		t.Fatalf("want ErrOAuthInvalidClient (default DenyAll), got %v", err)
	}
}
