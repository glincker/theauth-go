package oidc_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
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
	"github.com/golang-jwt/jwt/v5"
)

// tenantIdP is a configurable fake IdP for template issuer, audience, preset
// and typed error tests. It serves discovery for any path ending in
// /.well-known/openid-configuration, so the same instance answers for the
// common, organizations and single tenant URLs.
type tenantIdP struct {
	srv *httptest.Server
	key *rsa.PrivateKey

	mu             sync.Mutex
	discoveryIss   string // issuer in the discovery document
	claims         jwt.MapClaims
	discoveryCode  int
	tokenCode      int
	tokenBody      string
	userinfoClaims map[string]any
}

func newTenantIdP(t *testing.T, discoveryIssuer string) *tenantIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &tenantIdP{key: key, discoveryIss: discoveryIssuer}
	mux := http.NewServeMux()
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		switch {
		case strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration"):
			if f.discoveryCode != 0 {
				w.WriteHeader(f.discoveryCode)
				return
			}
			iss := f.discoveryIss
			if iss == "" {
				iss = f.srv.URL
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer": iss, "authorization_endpoint": f.srv.URL + "/authorize",
				"token_endpoint": f.srv.URL + "/token", "jwks_uri": f.srv.URL + "/jwks",
				"userinfo_endpoint": f.srv.URL + "/userinfo",
			})
		case r.URL.Path == "/jwks":
			pub := f.key.PublicKey
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
				"kty": "RSA", "kid": "k1", "use": "sig", "alg": "RS256",
				"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
			}}})
		case r.URL.Path == "/token":
			if f.tokenCode != 0 {
				w.WriteHeader(f.tokenCode)
				_, _ = w.Write([]byte(f.tokenBody))
				return
			}
			tok := jwt.NewWithClaims(jwt.SigningMethodRS256, f.claims)
			tok.Header["kid"] = "k1"
			signed, _ := tok.SignedString(f.key)
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "id_token": signed})
		case r.URL.Path == "/userinfo":
			_ = json.NewEncoder(w).Encode(f.userinfoClaims)
		default:
			http.NotFound(w, r)
		}
	})
	return f
}

// setClaims installs ID token claims, filling the usual ones.
func (f *tenantIdP) setClaims(c jwt.MapClaims) {
	f.mu.Lock()
	defer f.mu.Unlock()
	base := jwt.MapClaims{"sub": "u1", "aud": clientID, "nonce": "n1", "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix()}
	for k, v := range c {
		base[k] = v
	}
	f.claims = base
}

// rewriter sends every request to the fake IdP while keeping the original
// URL's path, so presets that name real hosts can be exercised.
type rewriter struct{ to *url.URL }

func (r rewriter) RoundTrip(req *http.Request) (*http.Response, error) {
	c := req.Clone(req.Context())
	c.URL.Scheme, c.URL.Host = r.to.Scheme, r.to.Host
	return http.DefaultTransport.RoundTrip(c)
}

func (f *tenantIdP) client() *http.Client {
	u, _ := url.Parse(f.srv.URL)
	return &http.Client{Transport: rewriter{u}}
}

func login(t *testing.T, cfg oidc.Config) (*theauth.ProviderUser, error) {
	t.Helper()
	ctx := context.Background()
	p, err := oidc.New(ctx, cfg)
	if err != nil {
		return nil, err
	}
	np := p.(theauth.NonceProvider)
	tok, err := np.ExchangeCodeWithNonce(ctx, "code", "verifier", "http://x/cb", "n1")
	if err != nil {
		return nil, err
	}
	return p.UserInfo(ctx, tok)
}

func tenantIss(tid string) string { return "https://login.microsoftonline.com/" + tid + "/v2.0" }

const (
	tenantA = "11111111-1111-1111-1111-111111111111"
	tenantB = "22222222-2222-2222-2222-222222222222"
)

func TestEntraMultiTenantIssuerValidatedAgainstTid(t *testing.T) {
	tests := []struct {
		name    string
		tenant  string
		allowed []string
		claims  jwt.MapClaims
		wantErr string
	}{
		{"common accepts a tenant token", "common", nil, jwt.MapClaims{"iss": tenantIss(tenantA), "tid": tenantA}, ""},
		{"organizations accepts a tenant token", "organizations", nil, jwt.MapClaims{"iss": tenantIss(tenantA), "tid": tenantA}, ""},
		{"consumers accepts a personal tenant token", "consumers", nil, jwt.MapClaims{"iss": tenantIss("9188040d-6c67-4c5b-b112-36a304b66dad"), "tid": "9188040d-6c67-4c5b-b112-36a304b66dad"}, ""},
		{"allow list accepts its tenant", "common", []string{tenantA}, jwt.MapClaims{"iss": tenantIss(tenantA), "tid": tenantA}, ""},
		{"wrong tenant rejected by allow list", "common", []string{tenantA}, jwt.MapClaims{"iss": tenantIss(tenantB), "tid": tenantB}, "tenant is not allowed"},
		{"iss for one tenant with tid of another", "common", nil, jwt.MapClaims{"iss": tenantIss(tenantA), "tid": tenantB}, "does not match its tenant"},
		{"missing tid", "common", nil, jwt.MapClaims{"iss": tenantIss(tenantA)}, "tid"},
		{"tid that rewrites the template", "common", nil, jwt.MapClaims{"iss": tenantIss("x/../evil"), "tid": "x/../evil"}, "tid"},
		{"foreign issuer", "common", nil, jwt.MapClaims{"iss": "https://evil.example/" + tenantA + "/v2.0", "tid": tenantA}, "does not match its tenant"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			idp := newTenantIdP(t, "https://login.microsoftonline.com/{tenantid}/v2.0")
			idp.setClaims(tc.claims)
			cfg := oidc.Entra(tc.tenant, clientID, "secret")
			cfg.HTTPClient = idp.client()
			cfg.AllowedTenants = tc.allowed
			u, err := login(t, cfg)
			if tc.wantErr == "" {
				if err != nil || u.ID != "u1" {
					t.Fatalf("login: %v %+v", err, u)
				}
				return
			}
			var oe *oidc.Error
			if !errors.As(err, &oe) || oe.Stage != oidc.StageVerify || oe.Provider != "entra" {
				t.Fatalf("err = %v, want verify stage Error for entra", err)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestEntraSingleTenantComparesIssuerExactly(t *testing.T) {
	idp := newTenantIdP(t, tenantIss(tenantA))
	cfg := oidc.Entra(tenantA, clientID, "secret")
	cfg.HTTPClient = idp.client()

	idp.setClaims(jwt.MapClaims{"iss": tenantIss(tenantA), "tid": tenantA})
	if _, err := login(t, cfg); err != nil {
		t.Fatalf("own tenant: %v", err)
	}
	idp.setClaims(jwt.MapClaims{"iss": tenantIss(tenantB), "tid": tenantB})
	if _, err := login(t, cfg); err == nil {
		t.Fatal("token from another tenant accepted by a single tenant issuer")
	}
}

func TestTemplateIssuerConfigsAndAliasIssuer(t *testing.T) {
	idp := newTenantIdP(t, "https://login.microsoftonline.com/{tenantid}/v2.0")
	idp.setClaims(jwt.MapClaims{"iss": tenantIss(tenantA), "tid": tenantA})
	base := oidc.Config{ClientID: clientID, ClientSecret: "s", HTTPClient: idp.client(), AllowedTenants: []string{tenantA}}

	t.Run("literal template issuer", func(t *testing.T) {
		cfg := base
		cfg.Issuer = "https://login.microsoftonline.com/{tenantid}/v2.0"
		if _, err := login(t, cfg); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("alias issuer", func(t *testing.T) {
		cfg := base
		cfg.Issuer = "https://login.microsoftonline.com/common/v2.0"
		if _, err := login(t, cfg); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("unrelated alias is refused at discovery", func(t *testing.T) {
		cfg := base
		cfg.Issuer = "https://login.microsoftonline.com/not-an-alias/v2.0"
		if _, err := oidc.New(context.Background(), cfg); err == nil {
			t.Fatal("issuer that is neither the template nor an alias was accepted")
		}
	})
}

func TestAdditionalAudiences(t *testing.T) {
	tests := []struct {
		name       string
		additional []string
		claims     jwt.MapClaims
		ok         bool
	}{
		{"client id alone", nil, jwt.MapClaims{}, true},
		{"unlisted foreign audience", nil, jwt.MapClaims{"aud": "mobile-app"}, false},
		{"listed audience", []string{"mobile-app"}, jwt.MapClaims{"aud": "mobile-app"}, true},
		{"unrelated audience with a list", []string{"mobile-app"}, jwt.MapClaims{"aud": "other"}, false},
		{"multi aud with matching azp", []string{"mobile-app"}, jwt.MapClaims{"aud": []string{clientID, "mobile-app"}, "azp": clientID}, true},
		{"multi aud with wrong azp", []string{"mobile-app"}, jwt.MapClaims{"aud": []string{clientID, "mobile-app"}, "azp": "mobile-app"}, false},
		{"multi aud without azp", []string{"mobile-app"}, jwt.MapClaims{"aud": []string{clientID, "mobile-app"}}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			idp := newTenantIdP(t, "")
			iss := idp.srv.URL
			claims := jwt.MapClaims{"iss": iss}
			for k, v := range tc.claims {
				claims[k] = v
			}
			idp.setClaims(claims)
			_, err := login(t, oidc.Config{
				Issuer: iss, ClientID: clientID, ClientSecret: "s", AllowInsecureHTTP: true,
				AdditionalAudiences: tc.additional,
			})
			if (err == nil) != tc.ok {
				t.Fatalf("err = %v, want ok=%v", err, tc.ok)
			}
		})
	}
}

func TestTypedErrorsCarryStageStatusAndNoSecrets(t *testing.T) {
	const secret = "s3cr3t-value-do-not-leak"
	ctx := context.Background()

	t.Run("discovery status", func(t *testing.T) {
		idp := newTenantIdP(t, "")
		idp.discoveryCode = http.StatusServiceUnavailable
		_, err := oidc.New(ctx, oidc.Config{Issuer: idp.srv.URL, ClientID: clientID, ClientSecret: secret, AllowInsecureHTTP: true})
		var oe *oidc.Error
		if !errors.As(err, &oe) || oe.Stage != oidc.StageDiscovery || oe.Status != 503 || oe.Provider != "oidc" {
			t.Fatalf("err = %#v", err)
		}
	})
	t.Run("discovery transport error hides the url", func(t *testing.T) {
		_, err := oidc.New(ctx, oidc.Config{Issuer: "http://127.0.0.1:1", ClientID: clientID, ClientSecret: secret, AllowInsecureHTTP: true, Name: "custom"})
		var oe *oidc.Error
		if !errors.As(err, &oe) || oe.Stage != oidc.StageDiscovery || oe.Provider != "custom" {
			t.Fatalf("err = %#v", err)
		}
		if strings.Contains(err.Error(), "127.0.0.1:1/") {
			t.Fatalf("message leaks the request url: %v", err)
		}
	})
	t.Run("exchange status and body are not leaked", func(t *testing.T) {
		idp := newTenantIdP(t, "")
		idp.tokenCode = http.StatusBadRequest
		idp.tokenBody = `{"error":"invalid_grant","client_secret":"` + secret + `"}`
		_, err := login(t, oidc.Config{Issuer: idp.srv.URL, ClientID: clientID, ClientSecret: secret, AllowInsecureHTTP: true})
		var oe *oidc.Error
		if !errors.As(err, &oe) || oe.Stage != oidc.StageExchange || oe.Status != 400 {
			t.Fatalf("err = %#v", err)
		}
		if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "invalid_grant") {
			t.Fatalf("message leaks response content: %v", err)
		}
	})
	t.Run("verify stage", func(t *testing.T) {
		idp := newTenantIdP(t, "")
		idp.setClaims(jwt.MapClaims{"iss": "https://evil.example"})
		_, err := login(t, oidc.Config{Issuer: idp.srv.URL, ClientID: clientID, ClientSecret: secret, AllowInsecureHTTP: true})
		var oe *oidc.Error
		if !errors.As(err, &oe) || oe.Stage != oidc.StageVerify {
			t.Fatalf("err = %#v", err)
		}
	})
	t.Run("nonce mismatch is a verify error", func(t *testing.T) {
		idp := newTenantIdP(t, "")
		idp.setClaims(jwt.MapClaims{"iss": idp.srv.URL, "nonce": "other"})
		_, err := login(t, oidc.Config{Issuer: idp.srv.URL, ClientID: clientID, ClientSecret: secret, AllowInsecureHTTP: true})
		var oe *oidc.Error
		if !errors.As(err, &oe) || oe.Stage != oidc.StageVerify {
			t.Fatalf("err = %#v", err)
		}
	})
}

func TestPresets(t *testing.T) {
	tests := []struct {
		name          string
		cfg           oidc.Config
		wantName      string
		wantIssuer    string
		wantDiscovery string
	}{
		{"entra common", oidc.Entra("common", "c", "s"), "entra", "https://login.microsoftonline.com/{tenantid}/v2.0", "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration"},
		{"entra consumers", oidc.Entra("consumers", "c", "s"), "entra", "https://login.microsoftonline.com/{tenantid}/v2.0", "https://login.microsoftonline.com/consumers/v2.0/.well-known/openid-configuration"},
		{"entra tenant", oidc.Entra(tenantA, "c", "s"), "entra", tenantIss(tenantA), tenantIss(tenantA) + "/.well-known/openid-configuration"},
		{"okta org", oidc.Okta("dev-1.okta.com", "c", "s"), "okta", "https://dev-1.okta.com", "https://dev-1.okta.com/.well-known/openid-configuration"},
		{"okta custom server", oidc.Okta("https://dev-1.okta.com/oauth2/default/", "c", "s"), "okta", "https://dev-1.okta.com/oauth2/default", "https://dev-1.okta.com/oauth2/default/.well-known/openid-configuration"},
		{"keycloak", oidc.Keycloak("https://sso.example.com/", "acme", "c", "s"), "keycloak", "https://sso.example.com/realms/acme", "https://sso.example.com/realms/acme/.well-known/openid-configuration"},
		{"authentik", oidc.Authentik("https://auth.example.com", "myapp", "c", "s"), "authentik", "https://auth.example.com/application/o/myapp/", "https://auth.example.com/application/o/myapp/.well-known/openid-configuration"},
		{"auth0", oidc.Auth0("example.us.auth0.com", "c", "s"), "auth0", "https://example.us.auth0.com/", "https://example.us.auth0.com/.well-known/openid-configuration"},
		{"cognito", oidc.Cognito("us-east-1", "us-east-1_AbCdEfGhI", "c", "s"), "cognito", "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_AbCdEfGhI", "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_AbCdEfGhI/.well-known/openid-configuration"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := tc.cfg
			if c.Name != tc.wantName || c.Issuer != tc.wantIssuer || c.DiscoveryURL != tc.wantDiscovery {
				t.Fatalf("got name=%q issuer=%q discovery=%q", c.Name, c.Issuer, c.DiscoveryURL)
			}
			if c.ClientID != "c" || c.ClientSecret != "s" || len(c.Scopes) < 3 || c.Scopes[0] != "openid" {
				t.Fatalf("credentials or scopes wrong: %+v", c)
			}
		})
	}
}

func TestPresetDiscoveryAndClaimMapping(t *testing.T) {
	idp := newTenantIdP(t, "https://example.us.auth0.com/")
	idp.setClaims(jwt.MapClaims{
		"iss": "https://example.us.auth0.com/", "email": "ada@example.com", "email_verified": true,
		"name": "Ada", "picture": "https://img/x.png",
	})
	cfg := oidc.Auth0("example.us.auth0.com", clientID, "s")
	cfg.HTTPClient = idp.client()
	u, err := login(t, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if u.Email != "ada@example.com" || !u.EmailVerified || u.Name != "Ada" || u.AvatarURL != "https://img/x.png" {
		t.Fatalf("profile: %+v", u)
	}

	t.Run("cognito reads string email_verified", func(t *testing.T) {
		const iss = "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_AbCdEfGhI"
		idp := newTenantIdP(t, iss)
		idp.setClaims(jwt.MapClaims{"iss": iss, "email": "cog@example.com", "email_verified": "true", "name": "Cog"})
		cfg := oidc.Cognito("us-east-1", "us-east-1_AbCdEfGhI", clientID, "s")
		cfg.HTTPClient = idp.client()
		u, err := login(t, cfg)
		if err != nil {
			t.Fatal(err)
		}
		if u.Email != "cog@example.com" || !u.EmailVerified || u.Name != "Cog" {
			t.Fatalf("profile: %+v", u)
		}
	})

	t.Run("entra does not trust a plain email_verified claim", func(t *testing.T) {
		idp := newTenantIdP(t, "https://login.microsoftonline.com/{tenantid}/v2.0")
		idp.setClaims(jwt.MapClaims{"iss": tenantIss(tenantA), "tid": tenantA, "email": "ada@corp.com", "email_verified": true})
		cfg := oidc.Entra("common", clientID, "s")
		cfg.HTTPClient = idp.client()
		u, err := login(t, cfg)
		if err != nil {
			t.Fatal(err)
		}
		if u.EmailVerified {
			t.Fatal("entra preset must not take email_verified; only xms_edov")
		}
		idp.setClaims(jwt.MapClaims{"iss": tenantIss(tenantA), "tid": tenantA, "email": "ada@corp.com", "xms_edov": true})
		if u, err = login(t, cfg); err != nil || !u.EmailVerified {
			t.Fatalf("xms_edov: %v %+v", err, u)
		}
	})

	t.Run("custom claim mapping", func(t *testing.T) {
		idp := newTenantIdP(t, "")
		idp.setClaims(jwt.MapClaims{"iss": idp.srv.URL, "mail": "x@y.com", "display": "X Y", "oid": "object-1"})
		u, err := login(t, oidc.Config{
			Issuer: idp.srv.URL, ClientID: clientID, ClientSecret: "s", AllowInsecureHTTP: true,
			Claims: oidc.ClaimMapping{Subject: "oid", Email: "mail", Name: "display"},
		})
		if err != nil || u.ID != "object-1" || u.Email != "x@y.com" || u.Name != "X Y" {
			t.Fatalf("mapped profile: %v %+v", err, u)
		}
	})
}
