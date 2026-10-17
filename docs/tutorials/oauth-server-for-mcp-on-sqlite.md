# Run an OAuth 2.1 server for your MCP server on SQLite

MCP clients such as editors and coding agents expect an OAuth 2.1 authorization server, with dynamic client registration and PKCE, in front of your MCP endpoint, and standing one up usually means another service and another database.

In this tutorial you run the authorization server inside your own Go process with one SQLite file for storage. You register a public client, run the authorization code flow with PKCE, and guard an MCP endpoint with the resource server middleware. At the end you revoke a token and see which validator notices.

## Prerequisites

- Go 1.26 or newer, because `storage/sqlite` and its pure Go driver (`modernc.org/sqlite`, no cgo) declare `go 1.26.0`.
- A module to work in:

```sh
go get github.com/glincker/theauth-go/v2@latest
go get github.com/glincker/theauth-go/storage/sqlite@latest
go get github.com/glincker/theauth-go/mcpresource@latest
go get github.com/go-chi/chi/v5 github.com/oklog/ulid/v2 modernc.org/sqlite
```

The SQLite authorization server needs root v2.11.0 or later and a `storage/sqlite` release newer than v0.2.0 (v0.3.0 once tagged). Until that tag exists, use `@main` for `storage/sqlite`.

## 1. Imports and constants

Everything below goes into one `main()`. The names `example.com` are placeholders; the demo never touches the network beyond a local test server.

```go
import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"time"

	"github.com/glincker/theauth-go/mcpresource"
	sqlitestore "github.com/glincker/theauth-go/storage/sqlite"
	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/crypto"
	"github.com/go-chi/chi/v5"
	"github.com/oklog/ulid/v2"
	_ "modernc.org/sqlite"
)

const (
	issuer   = "https://auth.example.com"
	resource = "https://mcp.example.com/mcp"
	redirect = "http://127.0.0.1:8976/callback"
	pragmas  = "?_pragma=foreign_keys(1)&_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)&_txlock=immediate"
)
```

## 2. Open and migrate the SQLite file

```go
	// Step 1: one SQLite file, migrated, as the only store.
	db, err := sql.Open("sqlite", "file:oauth-demo.db"+pragmas)
	if err != nil {
		log.Fatal(err)
	}
	if err := sqlitestore.Migrate(ctx, db); err != nil {
		log.Fatal(err)
	}
	store, err := sqlitestore.New(db)
	if err != nil {
		log.Fatal(err)
	}

```

The pragmas turn on foreign keys, WAL mode and a busy timeout. One process should own the file.

## 3. Configure the authorization server

```go
	// Step 2: the authorization server.
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		log.Fatal(err)
	}
	a, err := theauth.New(theauth.Config{
		Storage:       store,
		BaseURL:       issuer,
		EncryptionKey: key,
		AuthorizationServer: &theauth.AuthorizationServerConfig{
			Issuer: issuer,
			Resources: []theauth.ProtectedResource{{
				Identifier: resource,
				Scopes:     []string{"files.read", "files.write"},
			}},
			AllowAnonymousRegistration: true,
			AccessTokenRevocation:      true,
			RegistrationTokens:         []string{"demo-initial-access-token"},
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	defer a.Close()
	r := chi.NewRouter()
	a.Mount(r)
	as := httptest.NewServer(r)
	defer as.Close()
	hc := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

```

`Resources` lists your MCP endpoint and the scopes it understands. `AllowAnonymousRegistration` lets MCP clients register themselves, which is what they expect. `RegistrationTokens` is the alternative: an operator-issued bearer token needed to register. `AccessTokenRevocation` stores a denylist entry for each revoked token until it expires.

## 4. Register clients

An MCP client registers itself as a public client (no secret). Your MCP server registers as a confidential client so it can call token introspection later.

```go
	// Step 3: dynamic client registration, the way an MCP client does it.
	reg := `{"client_name":"Demo MCP client","redirect_uris":["` + redirect + `"],` +
		`"grant_types":["authorization_code","refresh_token"],"response_types":["code"],"token_endpoint_auth_method":"none"}`
	res, err := hc.Post(as.URL+"/oauth/register", "application/json", strings.NewReader(reg))
	if err != nil {
		log.Fatal(err)
	}
	var client map[string]any
	_ = json.NewDecoder(res.Body).Decode(&client)
	_ = res.Body.Close()
	clientID, _ := client["client_id"].(string)
	fmt.Println("register:", res.StatusCode, "client_secret issued:", client["client_secret"] != nil)

	// The MCP server also registers itself as a confidential client (with an
	// operator initial access token) so it can call token introspection.
	rsReg := `{"client_name":"demo-mcp-server","redirect_uris":["https://mcp.example.com/cb"],` +
		`"grant_types":["authorization_code"],"token_endpoint_auth_method":"client_secret_basic"}`
	rsReq, _ := http.NewRequest(http.MethodPost, as.URL+"/oauth/register", strings.NewReader(rsReg))
	rsReq.Header.Set("Content-Type", "application/json")
	rsReq.Header.Set("Authorization", "Bearer demo-initial-access-token")
	res, err = hc.Do(rsReq)
	if err != nil {
		log.Fatal(err)
	}
	var rs map[string]any
	_ = json.NewDecoder(res.Body).Decode(&rs)
	_ = res.Body.Close()
	rsID, _ := rs["client_id"].(string)
	rsSecret, _ := rs["client_secret"].(string)

```

## 5. Authorize with PKCE

Your real sign-in page sends the browser to `/oauth/authorize`. An anonymous request is redirected to login. To keep the demo short, I create a user and a live session directly, then send the session cookie.

```go
	// Step 4: authorize with PKCE. A real app sends the browser to its own
	// sign-in page; here we create a user and a live session directly.
	u, err := store.CreateUser(ctx, theauth.User{ID: ulid.Make(), Email: "alice@example.com", CreatedAt: time.Now()})
	if err != nil {
		log.Fatal(err)
	}
	sessTok, _ := crypto.NewToken()
	if _, err := store.CreateSession(ctx, theauth.Session{
		ID: ulid.Make(), UserID: u.ID, TokenHash: crypto.HashToken(sessTok), ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		log.Fatal(err)
	}
	verifier, _ := crypto.NewCodeVerifier()
	q := url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {redirect},
		"scope": {"files.read"}, "state": {"xyz"}, "resource": {resource},
		"code_challenge": {crypto.CodeChallenge(verifier)}, "code_challenge_method": {"S256"},
	}
	req, _ := http.NewRequest(http.MethodGet, as.URL+"/oauth/authorize?"+q.Encode(), nil)
	req.AddCookie(&http.Cookie{Name: "theauth_session", Value: sessTok})
	res, err = hc.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	_ = res.Body.Close()
	loc, _ := url.Parse(res.Header.Get("Location"))
	fmt.Println("authorize:", res.StatusCode, "state:", loc.Query().Get("state"), "iss:", loc.Query().Get("iss"))

```

Only `S256` is accepted as the challenge method. The redirect carries `state` and `iss` back to the client.

## 6. Exchange the code and guard the MCP endpoint

```go
	// Step 5: exchange the code with the PKCE verifier.
	res, err = hc.PostForm(as.URL+"/oauth/token", url.Values{
		"grant_type": {"authorization_code"}, "client_id": {clientID}, "code": {loc.Query().Get("code")},
		"code_verifier": {verifier}, "redirect_uri": {redirect}, "resource": {resource},
	})
	if err != nil {
		log.Fatal(err)
	}
	var tok map[string]any
	_ = json.NewDecoder(res.Body).Decode(&tok)
	_ = res.Body.Close()
	at, _ := tok["access_token"].(string)
	fmt.Println("token:", res.StatusCode, tok["token_type"], "scope:", tok["scope"], "refresh token issued:", tok["refresh_token"] != nil)

```

Now the resource server. `mcpresource.New` takes your resource identifier and validates the signature against the server's JWKS, the audience, and the scopes. A second validator adds a revocation check that asks the server through introspection.

```go
	// Step 6: the MCP server checks tokens with the resource server middleware.
	v := mcpresource.New(resource, mcpresource.WithJWKS(as.URL+"/oauth/jwks"))
	mcp := httptest.NewServer(v.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, _ := v.Principal(r.Context())
		fmt.Fprintf(w, "hello %s, scope %v", p.Subject, p.Scope)
	})))
	defer mcp.Close()
	checked := mcpresource.New(resource,
		mcpresource.WithJWKS(as.URL+"/oauth/jwks"),
		mcpresource.WithIntrospection(as.URL+"/oauth/introspect", rsID, rsSecret),
		mcpresource.WithRevocationChecker(mcpresource.RevocationCheckerFunc(
			func(_ context.Context, token string, _ *mcpresource.Principal) (bool, error) {
				req, _ := http.NewRequest(http.MethodPost, as.URL+"/oauth/introspect", strings.NewReader(url.Values{"token": {token}}.Encode()))
				req.SetBasicAuth(rsID, rsSecret)
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				res, err := hc.Do(req)
				if err != nil {
					return false, err
				}
				defer func() { _ = res.Body.Close() }()
				var out map[string]any
				_ = json.NewDecoder(res.Body).Decode(&out)
				active, _ := out["active"].(bool)
				return !active, nil
			})))
	strict := httptest.NewServer(checked.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {})))
	defer strict.Close()
	call := func(target, token string) int {
		req, _ := http.NewRequest(http.MethodPost, target, nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		res, err := hc.Do(req)
		if err != nil {
			log.Fatal(err)
		}
		defer func() { _ = res.Body.Close() }()
		return res.StatusCode
	}
	fmt.Println("no token:", call(mcp.URL, ""))
	fmt.Println("valid token:", call(mcp.URL, at))

```

## 7. Revoke and compare

```go
	// Step 7: revoke, then see which validator notices.
	res, err = hc.PostForm(as.URL+"/oauth/revoke", url.Values{"token": {at}, "token_type_hint": {"access_token"}, "client_id": {clientID}})
	if err != nil {
		log.Fatal(err)
	}
	_ = res.Body.Close()
	fmt.Println("revoke:", res.StatusCode)
	fmt.Println("after revoke, JWKS only validator:", call(mcp.URL, at))
	fmt.Println("after revoke, with RevocationChecker:", call(strict.URL, at))
}
```

## Discovery and what a client sees

Clients do not need your config. The server publishes `/.well-known/oauth-authorization-server`, with the authorization, token, JWKS, registration, revocation and introspection endpoints under `/oauth/`, and `code_challenge_methods_supported` set to `["S256"]`. The protected resource document at `/.well-known/oauth-protected-resource` names your resource and its authorization server. The test file asserts all of this, so you can use it as a checklist when you point a real MCP client at your own instance.

Dynamic registration is picky in a useful way: the test registers a client with an `http://` redirect on a non-loopback host and expects a 400. Loopback redirects like `http://127.0.0.1:8976/callback` are what desktop MCP clients use, and those pass.

## What the output means

Run it and you get:

```text
register: 201 client_secret issued: false
authorize: 302 state: xyz iss: https://auth.example.com
token: 200 Bearer scope: files.read refresh token issued: true
no token: 401
valid token: 200
revoke: 200
after revoke, JWKS only validator: 200
after revoke, with RevocationChecker: 401
```

The public client got no secret. The authorization code came back with the same `state` and the issuer. A call without a token is a 401 whose `WWW-Authenticate` header points at `/.well-known/oauth-protected-resource/mcp`, which is how a client finds the authorization server.

The last two lines are the caveat. After revocation, the validator that only checks the JWT against the JWKS still says 200. It works offline and cannot know. The one with a `RevocationChecker` says 401. Pick the second for anything an agent can use to do damage. Tokens that carry an `act` chain or a delegation grant are always rechecked through introspection.

## Limits

- This is a test-grade demo. The sign-in step is faked, and the server is plain `httptest`, not TLS.
- SQLite means one writer process. Do not point two replicas at the same file. The introspection cache is per process too.
- Open dynamic registration lets anyone create a client record. Rate limit it, or require `RegistrationTokens`.
- Expired rows are not swept for you. Call `store.SweepExpired` on a ticker.
- Revocation through the denylist is only as fresh as the resource server's introspection cache (`IntrospectionCacheTTL`).

The flow comes from [`storage/sqlite/oauth_e2e_test.go`](https://github.com/glincker/theauth-go/blob/main/storage/sqlite/oauth_e2e_test.go) and [`oauth_mcpresource_test.go`](https://github.com/glincker/theauth-go/blob/main/storage/sqlite/oauth_mcpresource_test.go), which also cover refresh rotation, code replay and restart durability.

## Next

- [Single binary with SQLite example](https://github.com/glincker/theauth-go/tree/main/examples/single-binary-sqlite)
- [OAuth server on SQLite reference](../mcp-oauth-sqlite.md)
- [Pluggable stores](../pluggable-stores.md)
- [Access token policy](../access-token-policy.md)
- [Host-owned OAuth consent](../oauth-consent.md) and its tutorial, [Let your app own the OAuth consent screen](host-owned-oauth-consent-screen.md)
