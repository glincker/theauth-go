package oidc_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/provider/oidc"
	"github.com/glincker/theauth-go/v2/storage/memory"
	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
)

const clientID = "cid"

type fakeIdP struct {
	srv  *httptest.Server
	key  *rsa.PrivateKey
	mu   sync.Mutex
	opts idpOpts
	// recorded from the authorize redirect by the test
	challenge string
	nonce     string
	// recorded at the token endpoint
	gotVerifier string
}

type idpOpts struct {
	nonceOverride string
	aud           string
	signWith      *rsa.PrivateKey
	email         string
	emailVerified bool
	expired       bool
	issuer        string
}

func newIdP(t *testing.T) *fakeIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIdP{key: key, opts: idpOpts{email: "oidc@corp.com", emailVerified: true}}
	mux := http.NewServeMux()
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                f.srv.URL,
			"authorization_endpoint":                f.srv.URL + "/authorize",
			"token_endpoint":                        f.srv.URL + "/token",
			"jwks_uri":                              f.srv.URL + "/jwks",
			"code_challenge_methods_supported":      []string{"S256"},
			"token_endpoint_auth_methods_supported": []string{"client_secret_post"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		pub := key.PublicKey
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": "k1", "use": "sig", "alg": "RS256",
			"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f.mu.Lock()
		defer f.mu.Unlock()
		f.gotVerifier = r.Form.Get("code_verifier")
		sum := sha256.Sum256([]byte(f.gotVerifier))
		if base64.RawURLEncoding.EncodeToString(sum[:]) != f.challenge {
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
		nonce := f.nonce
		if f.opts.nonceOverride != "" {
			nonce = f.opts.nonceOverride
		}
		aud := clientID
		if f.opts.aud != "" {
			aud = f.opts.aud
		}
		iss := f.srv.URL
		if f.opts.issuer != "" {
			iss = f.opts.issuer
		}
		exp := time.Now().Add(time.Hour)
		if f.opts.expired {
			exp = time.Now().Add(-time.Hour)
		}
		claims := jwt.MapClaims{
			"iss": iss, "aud": aud, "sub": "user-1", "exp": exp.Unix(), "iat": time.Now().Unix(),
			"nonce": nonce, "email": f.opts.email, "email_verified": f.opts.emailVerified, "name": "Oidc User",
		}
		signer := key
		if f.opts.signWith != nil {
			signer = f.opts.signWith
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tok.Header["kid"] = "k1"
		signed, err := tok.SignedString(signer)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "id_token": signed, "expires_in": 3600})
	})
	return f
}

func (f *fakeIdP) set(o idpOpts) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if o.email == "" {
		o.email, o.emailVerified = "oidc@corp.com", true
	}
	f.opts = o
}

type env struct {
	srv *httptest.Server
	idp *fakeIdP
}

func newEnv(t *testing.T, oc *theauth.OAuthConfig) env {
	t.Helper()
	idp := newIdP(t)
	prov, err := oidc.New(context.Background(), oidc.Config{
		Name: "corp", Issuer: idp.srv.URL, ClientID: clientID, ClientSecret: "sec", AllowInsecureHTTP: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	a, err := theauth.New(theauth.Config{
		Storage: memory.New(), BaseURL: "http://localhost", EncryptionKey: key,
		Providers: []theauth.Provider{prov}, OAuth: oc, PostLoginRedirect: "/home",
		RateLimitPerIP: 1000, RateLimitPerEmail: 1000,
	})
	if err != nil {
		t.Fatal(err)
	}
	r := chi.NewRouter()
	a.Mount(r)
	srv := httptest.NewServer(r)
	t.Cleanup(func() { srv.Close(); a.Close() })
	return env{srv: srv, idp: idp}
}

var noFollow = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

func (e env) login(t *testing.T) *http.Response {
	t.Helper()
	resp, err := noFollow.Get(e.srv.URL + "/auth/providers/corp/start")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	loc, _ := url.Parse(resp.Header.Get("Location"))
	q := loc.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		t.Fatalf("authorize URL lacks PKCE S256: %s", loc)
	}
	if q.Get("nonce") == "" {
		t.Fatalf("authorize URL lacks nonce: %s", loc)
	}
	e.idp.mu.Lock()
	e.idp.challenge, e.idp.nonce = q.Get("code_challenge"), q.Get("nonce")
	e.idp.mu.Unlock()
	req, _ := http.NewRequest("GET", e.srv.URL+"/auth/providers/corp/callback?code=c&state="+url.QueryEscape(q.Get("state")), nil)
	for _, c := range resp.Cookies() {
		req.AddCookie(c)
	}
	cb, err := noFollow.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = cb.Body.Close()
	return cb
}

func TestOIDCLoginSucceedsWithPKCEAndNonce(t *testing.T) {
	e := newEnv(t, nil)
	if resp := e.login(t); resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/home" {
		t.Fatalf("callback: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if e.idp.gotVerifier == "" {
		t.Fatal("token endpoint never saw a code_verifier")
	}
}

func TestOIDCRejectsBadIDTokens(t *testing.T) {
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]idpOpts{
		"wrong nonce":    {nonceOverride: "attacker-nonce"},
		"wrong audience": {aud: "someone-else"},
		"forged key":     {signWith: otherKey},
		"expired":        {expired: true},
		"wrong issuer":   {issuer: "https://evil.example"},
	}
	for name, o := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, nil)
			e.idp.set(o)
			if resp := e.login(t); resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("want 400 got %d", resp.StatusCode)
			}
		})
	}
}

func TestOIDCSignupPolicyUsesVerifiedEmail(t *testing.T) {
	e := newEnv(t, &theauth.OAuthConfig{Signup: theauth.OAuthSignupAllowedDomains, AllowedEmailDomains: []string{"corp.com"}})
	if resp := e.login(t); resp.StatusCode != http.StatusFound {
		t.Fatalf("allowed domain: %d", resp.StatusCode)
	}
	e2 := newEnv(t, &theauth.OAuthConfig{Signup: theauth.OAuthSignupAllowedDomains, AllowedEmailDomains: []string{"corp.com"}})
	e2.idp.set(idpOpts{email: "x@corp.com", emailVerified: false})
	if resp := e2.login(t); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unverified email must be refused: %d", resp.StatusCode)
	}
}

func TestOIDCDiscoveryValidation(t *testing.T) {
	idp := newIdP(t)
	ctx := context.Background()
	if _, err := oidc.New(ctx, oidc.Config{Issuer: idp.srv.URL, ClientID: "c", ClientSecret: "s"}); err == nil {
		t.Fatal("http issuer must be refused without AllowInsecureHTTP")
	}
	if _, err := oidc.New(ctx, oidc.Config{Issuer: idp.srv.URL + "/", ClientID: "c", ClientSecret: "s", AllowInsecureHTTP: true}); err == nil {
		t.Fatal("issuer that differs from the discovery document must be refused")
	}
	if _, err := oidc.New(ctx, oidc.Config{Issuer: idp.srv.URL}); err == nil {
		t.Fatal("missing client credentials must be refused")
	}
	p, err := oidc.New(ctx, oidc.Config{Issuer: idp.srv.URL, ClientID: "c", ClientSecret: "s", AllowInsecureHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	if p.Name() != "oidc" || !strings.Contains(p.AuthURL("s", "c", "http://x/cb", nil), "code_challenge_method=S256") {
		t.Fatal("default name or PKCE param wrong")
	}
	if _, err := p.ExchangeCode(ctx, "c", "v", "http://x/cb"); err == nil {
		t.Fatal("plain ExchangeCode without nonce must fail")
	}
}

func TestOIDCDiscoveryOverrides(t *testing.T) {
	idp := newIdP(t)
	ctx := context.Background()
	base := oidc.Config{Issuer: idp.srv.URL, ClientID: "c", ClientSecret: "s", AllowInsecureHTTP: true}
	tests := []struct {
		name     string
		mod      func(*oidc.Config)
		wantErr  bool
		wantAuth string
	}{
		{"discovery url override", func(c *oidc.Config) { c.DiscoveryURL = idp.srv.URL + "/.well-known/openid-configuration" }, false, idp.srv.URL + "/authorize"},
		{"bad discovery url", func(c *oidc.Config) { c.DiscoveryURL = idp.srv.URL + "/nope" }, true, ""},
		{"endpoint override", func(c *oidc.Config) {
			c.Endpoints.AuthorizationEndpoint = "http://idp.local/custom-authorize"
		}, false, "http://idp.local/custom-authorize"},
		{"override must be https", func(c *oidc.Config) {
			c.AllowInsecureHTTP = false
			c.Issuer = "https://idp.invalid"
			c.DisableDiscovery = true
			c.Endpoints = oidc.Endpoints{AuthorizationEndpoint: "http://a", TokenEndpoint: "https://t", JWKSURI: "https://j"}
		}, true, ""},
		{"disabled discovery with endpoints", func(c *oidc.Config) {
			c.DisableDiscovery = true
			c.Endpoints = oidc.Endpoints{AuthorizationEndpoint: "http://a/auth", TokenEndpoint: "http://a/tok", JWKSURI: "http://a/jwks"}
		}, false, "http://a/auth"},
		{"disabled discovery missing endpoints", func(c *oidc.Config) { c.DisableDiscovery = true }, true, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			tc.mod(&cfg)
			p, err := oidc.New(ctx, cfg)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tc.wantErr)
			}
			if err == nil && !strings.HasPrefix(p.AuthURL("s", "c", "http://x/cb", nil), tc.wantAuth+"?") {
				t.Fatalf("auth url %q does not start with %q", p.AuthURL("s", "c", "http://x/cb", nil), tc.wantAuth)
			}
		})
	}
}
