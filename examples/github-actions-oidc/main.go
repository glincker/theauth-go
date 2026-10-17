// GitHub Actions OIDC login, end to end and offline.
//
// It builds a GitHubActionsIssuer restricted to one repository, ref and
// environment, points its JWKS URL at a local server, signs fake GitHub style
// tokens with a local RSA key (the real GitHub keys are never fetched) and
// exchanges them through the jwt-bearer grant. The matching token is
// accepted, tokens from other repositories, refs or environments are not.
package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"time"

	oklog "github.com/oklog/ulid/v2"

	theauth "github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/storage/memory"
)

const (
	asIssuer = "https://auth.example.com"
	resource = "https://api.example.com/mcp"
)

// workflowMapper maps every verified token to one local user. A real mapper
// would look the repository up in your own table.
type workflowMapper struct{ id theauth.ULID }

func (m workflowMapper) Resolve(map[string]any) (theauth.ULID, error) { return m.id, nil }

func main() {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{
			"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "demo",
			"n": b64(key.N.Bytes()), "e": b64(big.NewInt(int64(key.E)).Bytes()),
		}}})
	}))
	defer jwks.Close()

	var user oklog.ULID
	_, _ = rand.Read(user[:])
	iss, err := theauth.GitHubActionsIssuer(theauth.GitHubActionsOptions{
		Repository:    "acme/app",
		Refs:          []string{"refs/heads/main"},
		Environment:   "production",
		Audience:      asIssuer,
		SubjectMapper: workflowMapper{id: theauth.ULID(user)},
	})
	if err != nil {
		log.Fatal(err)
	}
	// Demo only: fetch keys from the local server instead of GitHub.
	iss.JWKSURL = jwks.URL

	if _, err := theauth.GitHubActionsIssuer(theauth.GitHubActionsOptions{}); errors.Is(err, theauth.ErrGitHubActionsUnrestricted) {
		fmt.Println("unrestricted issuer refused:", err)
	}

	encKey := make([]byte, 32)
	_, _ = rand.Read(encKey)
	a, err := theauth.New(theauth.Config{
		Storage: memory.New(), BaseURL: asIssuer, EncryptionKey: encKey,
		AuthorizationServer: &theauth.AuthorizationServerConfig{
			Issuer:          asIssuer,
			Resources:       []theauth.ProtectedResource{{Identifier: resource, Scopes: []string{"api.read"}}},
			DisableRotation: true,
			JWTBearer: &theauth.JWTBearerConfig{
				TrustedJWTIssuers:        []theauth.TrustedJWTIssuer{iss},
				AllowPrivateJWKSNetworks: true, // the demo JWKS server is plain http on loopback
			},
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	defer a.Close()

	good := map[string]any{"repository": "acme/app", "ref": "refs/heads/main", "environment": "production"}
	cases := []struct {
		name   string
		claims map[string]any
	}{
		{"acme/app on main in production", good},
		{"another repository", with(good, "repository", "evil/app")},
		{"a feature branch", with(good, "ref", "refs/heads/feature")},
		{"no environment", with(good, "environment", nil)},
	}
	for _, c := range cases {
		_, err := a.JWTBearerGrant(context.Background(), theauth.TokenRequest{
			GrantType: "urn:ietf:params:oauth:grant-type:jwt-bearer", Resource: resource, Scope: []string{"api.read"},
		}, sign(key, c.claims))
		fmt.Printf("%-34s accepted=%v\n", c.name, err == nil)
	}
}

func with(m map[string]any, k string, v any) map[string]any {
	out := map[string]any{}
	for kk, vv := range m {
		out[kk] = vv
	}
	if v == nil {
		delete(out, k)
	} else {
		out[k] = v
	}
	return out
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// sign mints a GitHub shaped RS256 token for the demo.
func sign(key *rsa.PrivateKey, extra map[string]any) string {
	now := time.Now()
	p := map[string]any{
		"iss": theauth.GitHubActionsIssuerURL, "aud": asIssuer, "sub": "repo:acme/app:environment:production",
		"jti": fmt.Sprintf("%d", now.UnixNano()), "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
	}
	for k, v := range extra {
		p[k] = v
	}
	h, _ := json.Marshal(map[string]any{"alg": "RS256", "typ": "JWT", "kid": "demo"})
	pb, _ := json.Marshal(p)
	in := b64(h) + "." + b64(pb)
	sum := sha256.Sum256([]byte(in))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		log.Fatal(err)
	}
	return in + "." + b64(sig)
}
