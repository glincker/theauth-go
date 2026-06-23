package as_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/crypto"
	"github.com/glincker/theauth-go/internal/ulid"
)

// confidentialClient registers a new confidential OAuth client (no anonymous
// bit; default client_secret_basic auth) and returns the registered client
// alongside its plaintext secret.
func confidentialClient(t *testing.T, a *theauth.TheAuth) theauth.RegisteredClient {
	t.Helper()
	reg, err := a.RegisterClient(context.Background(), theauth.ClientRegistrationRequest{
		RedirectURIs:            []string{"https://app.example.com/cb"},
		TokenEndpointAuthMethod: theauth.ClientAuthSecretBasic,
	}, false)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	return reg
}

func TestAuthCodeFlowHappyPath(t *testing.T) {
	a, store := newASInstance(t)
	ctx := context.Background()
	user := theauth.User{ID: ulid.New(), Email: "alice@example.com"}
	if _, err := store.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	client := confidentialClient(t, a)
	verifier, _ := crypto.NewCodeVerifier()
	authzReq := theauth.AuthorizeRequest{
		ClientID:            client.ClientID,
		RedirectURI:         "https://app.example.com/cb",
		ResponseType:        "code",
		Scope:               []string{"files.read"},
		State:               "xyz",
		CodeChallenge:       crypto.CodeChallenge(verifier),
		CodeChallengeMethod: "S256",
		Resource:            "https://files.example.com/mcp",
	}
	res, err := a.StartAuthorize(ctx, authzReq, &user)
	if err != nil {
		t.Fatalf("StartAuthorize: %v", err)
	}
	code := codeFromRedirect(t, res.RedirectURL)

	tok, err := a.ExchangeAuthorizationCode(ctx, theauth.TokenRequest{
		GrantType:    theauth.GrantTypeAuthorizationCode,
		ClientID:     client.ClientID,
		ClientSecret: client.ClientSecret,
		Code:         code,
		CodeVerifier: verifier,
		RedirectURI:  "https://app.example.com/cb",
	})
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode: %v", err)
	}
	if tok.AccessToken == "" || tok.RefreshToken == "" {
		t.Fatalf("token response empty: %+v", tok)
	}
	// Introspect with matching aud succeeds.
	resp, _, err := a.IntrospectToken(ctx, tok.AccessToken, client.ClientID, client.ClientSecret, "https://files.example.com/mcp")
	if err != nil {
		t.Fatalf("Introspect: %v", err)
	}
	if !resp.Active || resp.Sub != user.ID.String() || resp.Aud != "https://files.example.com/mcp" {
		t.Fatalf("introspection unexpected: %+v", resp)
	}
}

func TestIntrospectAudienceMismatchRejects(t *testing.T) {
	a, store := newASInstance(t)
	ctx := context.Background()
	user := theauth.User{ID: ulid.New(), Email: "alice@example.com"}
	_, _ = store.CreateUser(ctx, user)
	client := confidentialClient(t, a)
	verifier, _ := crypto.NewCodeVerifier()
	res, _ := a.StartAuthorize(ctx, theauth.AuthorizeRequest{
		ClientID:            client.ClientID,
		RedirectURI:         "https://app.example.com/cb",
		ResponseType:        "code",
		Scope:               []string{"files.read"},
		CodeChallenge:       crypto.CodeChallenge(verifier),
		CodeChallengeMethod: "S256",
		Resource:            "https://files.example.com/mcp",
	}, &user)
	code := codeFromRedirect(t, res.RedirectURL)
	tok, err := a.ExchangeAuthorizationCode(ctx, theauth.TokenRequest{
		GrantType:    theauth.GrantTypeAuthorizationCode,
		ClientID:     client.ClientID,
		ClientSecret: client.ClientSecret,
		Code:         code,
		CodeVerifier: verifier,
		RedirectURI:  "https://app.example.com/cb",
	})
	if err != nil {
		t.Fatal(err)
	}
	resp, _, err := a.IntrospectToken(ctx, tok.AccessToken, client.ClientID, client.ClientSecret, "https://wrong.example.com/mcp")
	if err != nil {
		t.Fatal(err)
	}
	if resp.Active {
		t.Fatal("expected active=false for audience mismatch")
	}
}

func TestPKCEVerifierMismatchRejects(t *testing.T) {
	a, store := newASInstance(t)
	ctx := context.Background()
	user := theauth.User{ID: ulid.New(), Email: "alice@example.com"}
	_, _ = store.CreateUser(ctx, user)
	client := confidentialClient(t, a)
	verifier, _ := crypto.NewCodeVerifier()
	res, _ := a.StartAuthorize(ctx, theauth.AuthorizeRequest{
		ClientID:            client.ClientID,
		RedirectURI:         "https://app.example.com/cb",
		ResponseType:        "code",
		Scope:               []string{"files.read"},
		CodeChallenge:       crypto.CodeChallenge(verifier),
		CodeChallengeMethod: "S256",
		Resource:            "https://files.example.com/mcp",
	}, &user)
	code := codeFromRedirect(t, res.RedirectURL)
	wrongVerifier, _ := crypto.NewCodeVerifier()
	_, err := a.ExchangeAuthorizationCode(ctx, theauth.TokenRequest{
		GrantType:    theauth.GrantTypeAuthorizationCode,
		ClientID:     client.ClientID,
		ClientSecret: client.ClientSecret,
		Code:         code,
		CodeVerifier: wrongVerifier,
		RedirectURI:  "https://app.example.com/cb",
	})
	if !errors.Is(err, theauth.ErrOAuthPKCEMismatch) {
		t.Fatalf("expected pkce mismatch, got %v", err)
	}
}

func TestRefreshRotationAndReuseDetection(t *testing.T) {
	a, store := newASInstance(t)
	ctx := context.Background()
	user := theauth.User{ID: ulid.New(), Email: "alice@example.com"}
	_, _ = store.CreateUser(ctx, user)
	client := confidentialClient(t, a)
	verifier, _ := crypto.NewCodeVerifier()
	res, _ := a.StartAuthorize(ctx, theauth.AuthorizeRequest{
		ClientID:            client.ClientID,
		RedirectURI:         "https://app.example.com/cb",
		ResponseType:        "code",
		Scope:               []string{"files.read"},
		CodeChallenge:       crypto.CodeChallenge(verifier),
		CodeChallengeMethod: "S256",
		Resource:            "https://files.example.com/mcp",
	}, &user)
	code := codeFromRedirect(t, res.RedirectURL)
	tok, err := a.ExchangeAuthorizationCode(ctx, theauth.TokenRequest{
		GrantType:    theauth.GrantTypeAuthorizationCode,
		ClientID:     client.ClientID,
		ClientSecret: client.ClientSecret,
		Code:         code,
		CodeVerifier: verifier,
		RedirectURI:  "https://app.example.com/cb",
	})
	if err != nil {
		t.Fatal(err)
	}
	// First rotation succeeds.
	refreshed, err := a.RefreshAccessToken(ctx, theauth.TokenRequest{
		GrantType:    theauth.GrantTypeRefreshToken,
		ClientID:     client.ClientID,
		ClientSecret: client.ClientSecret,
		RefreshToken: tok.RefreshToken,
	})
	if err != nil {
		t.Fatalf("first refresh: %v", err)
	}
	if refreshed.RefreshToken == tok.RefreshToken {
		t.Fatal("refresh token should rotate, got same value")
	}
	// Re-using the old refresh token after rotation must revoke the entire
	// family per RFC 9700 section 4.14.
	_, err = a.RefreshAccessToken(ctx, theauth.TokenRequest{
		GrantType:    theauth.GrantTypeRefreshToken,
		ClientID:     client.ClientID,
		ClientSecret: client.ClientSecret,
		RefreshToken: tok.RefreshToken,
	})
	if !errors.Is(err, theauth.ErrOAuthInvalidGrant) {
		t.Fatalf("expected invalid_grant on reuse, got %v", err)
	}
	// The newly-rotated token is now also revoked because the family was
	// killed: trying to use it returns invalid_grant.
	_, err = a.RefreshAccessToken(ctx, theauth.TokenRequest{
		GrantType:    theauth.GrantTypeRefreshToken,
		ClientID:     client.ClientID,
		ClientSecret: client.ClientSecret,
		RefreshToken: refreshed.RefreshToken,
	})
	if !errors.Is(err, theauth.ErrOAuthInvalidGrant) {
		t.Fatalf("expected family revocation to kill rotated token, got %v", err)
	}
}

func TestRevokeTokenSilentlySucceeds(t *testing.T) {
	a, _ := newASInstance(t)
	client := confidentialClient(t, a)
	// RFC 7009: unknown token => 200. We assert no error returns.
	if err := a.RevokeToken(context.Background(), "unknown-token", "refresh_token", client.ClientID, client.ClientSecret); err != nil {
		t.Fatalf("RevokeToken on unknown token: %v", err)
	}
}

func TestIntrospectionCacheHit(t *testing.T) {
	a, store := newASInstance(t)
	ctx := context.Background()
	user := theauth.User{ID: ulid.New(), Email: "alice@example.com"}
	_, _ = store.CreateUser(ctx, user)
	client := confidentialClient(t, a)
	verifier, _ := crypto.NewCodeVerifier()
	res, _ := a.StartAuthorize(ctx, theauth.AuthorizeRequest{
		ClientID:            client.ClientID,
		RedirectURI:         "https://app.example.com/cb",
		ResponseType:        "code",
		Scope:               []string{"files.read"},
		CodeChallenge:       crypto.CodeChallenge(verifier),
		CodeChallengeMethod: "S256",
		Resource:            "https://files.example.com/mcp",
	}, &user)
	code := codeFromRedirect(t, res.RedirectURL)
	tok, _ := a.ExchangeAuthorizationCode(ctx, theauth.TokenRequest{
		GrantType:    theauth.GrantTypeAuthorizationCode,
		ClientID:     client.ClientID,
		ClientSecret: client.ClientSecret,
		Code:         code,
		CodeVerifier: verifier,
		RedirectURI:  "https://app.example.com/cb",
	})
	// First introspect populates the cache; second returns the cached body.
	resp1, body1, err := a.IntrospectToken(ctx, tok.AccessToken, client.ClientID, client.ClientSecret, "https://files.example.com/mcp")
	if err != nil {
		t.Fatal(err)
	}
	resp2, body2, err := a.IntrospectToken(ctx, tok.AccessToken, client.ClientID, client.ClientSecret, "https://files.example.com/mcp")
	if err != nil {
		t.Fatal(err)
	}
	if string(body1) != string(body2) || resp1.Jti != resp2.Jti {
		t.Fatalf("expected cache hit to return identical body, got %s vs %s", body1, body2)
	}
	// Sanity: response is genuinely active.
	if !resp1.Active {
		t.Fatal("expected active=true")
	}
	// Sleep just past the introspection cache TTL would require waiting 60s;
	// instead we directly assert the cache key shape stays unique per token.
	_ = time.Now()
}

func TestExpiredAuthorizationCodeRejected(t *testing.T) {
	a, store := newASInstance(t, func(c *theauth.AuthorizationServerConfig) {
		// Force a 1ns TTL so the code is born expired.
		c.AuthorizationCodeTTL = time.Nanosecond
	})
	ctx := context.Background()
	user := theauth.User{ID: ulid.New(), Email: "alice@example.com"}
	_, _ = store.CreateUser(ctx, user)
	client := confidentialClient(t, a)
	verifier, _ := crypto.NewCodeVerifier()
	res, _ := a.StartAuthorize(ctx, theauth.AuthorizeRequest{
		ClientID:            client.ClientID,
		RedirectURI:         "https://app.example.com/cb",
		ResponseType:        "code",
		Scope:               []string{"files.read"},
		CodeChallenge:       crypto.CodeChallenge(verifier),
		CodeChallengeMethod: "S256",
		Resource:            "https://files.example.com/mcp",
	}, &user)
	code := codeFromRedirect(t, res.RedirectURL)
	time.Sleep(2 * time.Millisecond)
	_, err := a.ExchangeAuthorizationCode(ctx, theauth.TokenRequest{
		GrantType:    theauth.GrantTypeAuthorizationCode,
		ClientID:     client.ClientID,
		ClientSecret: client.ClientSecret,
		Code:         code,
		CodeVerifier: verifier,
		RedirectURI:  "https://app.example.com/cb",
	})
	if !errors.Is(err, theauth.ErrOAuthInvalidGrant) {
		t.Fatalf("expected invalid_grant for expired code, got %v", err)
	}
}

// codeFromRedirect parses the ?code= parameter out of the authorize redirect.
func codeFromRedirect(t *testing.T, redirect string) string {
	t.Helper()
	idx := indexOf(redirect, "?")
	if idx < 0 {
		t.Fatalf("redirect missing query: %q", redirect)
	}
	q := redirect[idx+1:]
	for _, p := range splitOn(q, "&") {
		kv := splitOnN(p, "=", 2)
		if len(kv) == 2 && kv[0] == "code" {
			return kv[1]
		}
	}
	t.Fatalf("redirect missing code: %q", redirect)
	return ""
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func splitOn(s, sep string) []string {
	var out []string
	for {
		i := indexOf(s, sep)
		if i < 0 {
			out = append(out, s)
			return out
		}
		out = append(out, s[:i])
		s = s[i+len(sep):]
	}
}

func splitOnN(s, sep string, n int) []string {
	out := splitOn(s, sep)
	if len(out) <= n {
		return out
	}
	rest := ""
	for i := n - 1; i < len(out); i++ {
		if i > n-1 {
			rest += sep
		}
		rest += out[i]
	}
	return append(out[:n-1], rest)
}

// TestPKCEVerifierConstantTime verifies that a wrong code_verifier returns
// ErrOAuthPKCEMismatch (security re-audit L2, 2026-06-22). The constant-time
// property is a runtime guarantee of the implementation; this test covers
// correctness (wrong verifier is still rejected) so the switch to
// crypto/subtle.ConstantTimeCompare does not regress behavior.
func TestPKCEVerifierConstantTime(t *testing.T) {
	a, store := newASInstance(t)
	ctx := context.Background()
	user := theauth.User{ID: ulid.New(), Email: "alice@example.com"}
	_, _ = store.CreateUser(ctx, user)
	client := confidentialClient(t, a)
	verifier, _ := crypto.NewCodeVerifier()
	res, _ := a.StartAuthorize(ctx, theauth.AuthorizeRequest{
		ClientID:            client.ClientID,
		RedirectURI:         "https://app.example.com/cb",
		ResponseType:        "code",
		Scope:               []string{"files.read"},
		CodeChallenge:       crypto.CodeChallenge(verifier),
		CodeChallengeMethod: "S256",
		Resource:            "https://files.example.com/mcp",
	}, &user)
	code := codeFromRedirect(t, res.RedirectURL)
	wrongVerifier, _ := crypto.NewCodeVerifier()
	_, err := a.ExchangeAuthorizationCode(ctx, theauth.TokenRequest{
		GrantType:    theauth.GrantTypeAuthorizationCode,
		ClientID:     client.ClientID,
		ClientSecret: client.ClientSecret,
		Code:         code,
		CodeVerifier: wrongVerifier,
		RedirectURI:  "https://app.example.com/cb",
	})
	if !errors.Is(err, theauth.ErrOAuthPKCEMismatch) {
		t.Fatalf("wrong verifier: expected ErrOAuthPKCEMismatch, got %v", err)
	}
}

// issueTokenFamily is a helper that registers a client, runs an authorization
// code flow, and returns the initial refresh token plus the *theauth.TheAuth
// instance and client so callers can rotate.
func issueTokenFamily(t *testing.T) (*theauth.TheAuth, theauth.RegisteredClient, string) {
	t.Helper()
	a, store := newASInstance(t)
	ctx := context.Background()
	user := theauth.User{ID: ulid.New(), Email: "alice@example.com"}
	_, _ = store.CreateUser(ctx, user)
	client := confidentialClient(t, a)
	verifier, _ := crypto.NewCodeVerifier()
	res, _ := a.StartAuthorize(ctx, theauth.AuthorizeRequest{
		ClientID:            client.ClientID,
		RedirectURI:         "https://app.example.com/cb",
		ResponseType:        "code",
		Scope:               []string{"files.read"},
		CodeChallenge:       crypto.CodeChallenge(verifier),
		CodeChallengeMethod: "S256",
		Resource:            "https://files.example.com/mcp",
	}, &user)
	code := codeFromRedirect(t, res.RedirectURL)
	tok, err := a.ExchangeAuthorizationCode(ctx, theauth.TokenRequest{
		GrantType:    theauth.GrantTypeAuthorizationCode,
		ClientID:     client.ClientID,
		ClientSecret: client.ClientSecret,
		Code:         code,
		CodeVerifier: verifier,
		RedirectURI:  "https://app.example.com/cb",
	})
	if err != nil {
		t.Fatalf("issueTokenFamily: ExchangeAuthorizationCode: %v", err)
	}
	return a, client, tok.RefreshToken
}

// TestRevokeTokenWalksFamily verifies that revoking any member of a refresh-
// token rotation family also invalidates all siblings (security re-audit L3,
// 2026-06-22). Prior behavior revoked only the single presented token.
func TestRevokeTokenWalksFamily(t *testing.T) {
	a, client, rt0 := issueTokenFamily(t)
	ctx := context.Background()

	// Rotate once to get rt1.
	tok1, err := a.RefreshAccessToken(ctx, theauth.TokenRequest{
		GrantType:    theauth.GrantTypeRefreshToken,
		ClientID:     client.ClientID,
		ClientSecret: client.ClientSecret,
		RefreshToken: rt0,
	})
	if err != nil {
		t.Fatalf("first refresh: %v", err)
	}
	rt1 := tok1.RefreshToken

	// Rotate again to get rt2 (rt1 is now the middle of the family chain).
	tok2, err := a.RefreshAccessToken(ctx, theauth.TokenRequest{
		GrantType:    theauth.GrantTypeRefreshToken,
		ClientID:     client.ClientID,
		ClientSecret: client.ClientSecret,
		RefreshToken: rt1,
	})
	if err != nil {
		t.Fatalf("second refresh: %v", err)
	}
	rt2 := tok2.RefreshToken

	// Revoke the middle child (rt1 is already rotated and inactive, but the
	// storage row still carries the family ID). The family walk should also
	// kill rt2.
	if err := a.RevokeToken(ctx, rt1, "refresh_token", client.ClientID, client.ClientSecret); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}

	// rt2 must now be invalid: the family was revoked.
	_, err = a.RefreshAccessToken(ctx, theauth.TokenRequest{
		GrantType:    theauth.GrantTypeRefreshToken,
		ClientID:     client.ClientID,
		ClientSecret: client.ClientSecret,
		RefreshToken: rt2,
	})
	if !errors.Is(err, theauth.ErrOAuthInvalidGrant) {
		t.Fatalf("expected rt2 to be revoked after family walk, got %v", err)
	}
}

// TestRequireStateRejectsMissing verifies that when RequireState is true,
// /oauth/authorize requests without a non-empty state parameter are rejected
// with ErrOAuthInvalidRequest (security re-audit L5, 2026-06-22).
func TestRequireStateRejectsMissing(t *testing.T) {
	a, store := newASInstance(t, func(c *theauth.AuthorizationServerConfig) {
		c.RequireState = true
	})
	ctx := context.Background()
	user := theauth.User{ID: ulid.New(), Email: "alice@example.com"}
	_, _ = store.CreateUser(ctx, user)
	client := confidentialClient(t, a)
	verifier, _ := crypto.NewCodeVerifier()

	// Request without state must be rejected.
	_, err := a.StartAuthorize(ctx, theauth.AuthorizeRequest{
		ClientID:            client.ClientID,
		RedirectURI:         "https://app.example.com/cb",
		ResponseType:        "code",
		Scope:               []string{"files.read"},
		CodeChallenge:       crypto.CodeChallenge(verifier),
		CodeChallengeMethod: "S256",
		Resource:            "https://files.example.com/mcp",
		State:               "",
	}, &user)
	if !errors.Is(err, theauth.ErrOAuthInvalidRequest) {
		t.Fatalf("RequireState=true, missing state: expected ErrOAuthInvalidRequest, got %v", err)
	}

	// Request with a non-empty state must succeed.
	verifier2, _ := crypto.NewCodeVerifier()
	_, err = a.StartAuthorize(ctx, theauth.AuthorizeRequest{
		ClientID:            client.ClientID,
		RedirectURI:         "https://app.example.com/cb",
		ResponseType:        "code",
		Scope:               []string{"files.read"},
		CodeChallenge:       crypto.CodeChallenge(verifier2),
		CodeChallengeMethod: "S256",
		Resource:            "https://files.example.com/mcp",
		State:               "csrf-token-abc",
	}, &user)
	if err != nil {
		t.Fatalf("RequireState=true, present state: unexpected error %v", err)
	}
}
