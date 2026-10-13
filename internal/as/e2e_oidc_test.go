package as_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/crypto"
	"github.com/glincker/theauth-go/v2/internal/ulid"
	"github.com/glincker/theauth-go/v2/storage/memory"
	"github.com/go-chi/chi/v5"
)

// e2e_oidc_test.go: the OpenID Provider surface against the real router and
// memory store.

type oidcHarness struct {
	t       *testing.T
	auth    *theauth.TheAuth
	store   *memory.Store
	srv     *httptest.Server
	cookie  *http.Cookie
	user    theauth.User
	session theauth.Session

	mu      sync.Mutex
	logouts []string
	logoutC chan struct{}
	rp      *httptest.Server
}

func newOIDCHarness(t *testing.T, oidc *theauth.OIDCConfig) *oidcHarness {
	t.Helper()
	h := &oidcHarness{t: t, logoutC: make(chan struct{}, 4)}
	h.rp = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		h.mu.Lock()
		h.logouts = append(h.logouts, r.PostFormValue("logout_token"))
		h.mu.Unlock()
		h.logoutC <- struct{}{}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(h.rp.Close)
	h.auth, h.store = newASInstance(t, func(c *theauth.AuthorizationServerConfig) {
		c.RegistrationTokens = []string{"static-token"}
		c.OIDC = oidc
	})
	h.user = theauth.User{ID: ulid.New(), Email: "ada@example.com", Name: "Ada Lovelace"}
	now := time.Now()
	h.user.EmailVerifiedAt = &now
	if _, err := h.store.CreateUser(context.Background(), h.user); err != nil {
		t.Fatal(err)
	}
	raw, _ := crypto.NewToken()
	h.session = theauth.Session{
		ID: ulid.New(), UserID: h.user.ID, TokenHash: crypto.HashToken(raw),
		AuthLevel: theauth.AuthLevelFull, ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	if _, err := h.store.CreateSession(context.Background(), h.session); err != nil {
		t.Fatal(err)
	}
	h.cookie = &http.Cookie{Name: "theauth_session", Value: raw}
	r := chi.NewRouter()
	h.auth.Mount(r)
	h.srv = httptest.NewServer(r)
	t.Cleanup(h.srv.Close)
	return h
}

func (h *oidcHarness) get(path string, cookie bool, hdr map[string]string) (int, http.Header, []byte) {
	h.t.Helper()
	req, _ := http.NewRequest(http.MethodGet, h.srv.URL+path, nil)
	if cookie {
		req.AddCookie(h.cookie)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	return h.send(req)
}

func (h *oidcHarness) send(req *http.Request) (int, http.Header, []byte) {
	h.t.Helper()
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, b
}

func (h *oidcHarness) postForm(path string, form url.Values) (int, []byte) {
	h.t.Helper()
	req, _ := http.NewRequest(http.MethodPost, h.srv.URL+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	code, _, b := h.send(req)
	return code, b
}

func (h *oidcHarness) register(body string) string {
	h.t.Helper()
	req, _ := http.NewRequest(http.MethodPost, h.srv.URL+"/oauth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer static-token")
	code, _, b := h.send(req)
	if code != http.StatusCreated {
		h.t.Fatalf("register: %d %s", code, b)
	}
	var out struct {
		ClientID string `json:"client_id"`
	}
	_ = json.Unmarshal(b, &out)
	return out.ClientID
}

func (h *oidcHarness) registerRP(host string) string {
	return h.register(`{"client_name":"RP","redirect_uris":["https://` + host + `/cb"],
"token_endpoint_auth_method":"none","subject_type":"pairwise",
"post_logout_redirect_uris":["https://` + host + `/bye"],
"backchannel_logout_uri":"` + h.rp.URL + `/logout","backchannel_logout_session_required":true}`)
}

// login runs authorize and the code exchange, returning the token response.
func (h *oidcHarness) login(clientID, host, scope, nonce string) map[string]any {
	h.t.Helper()
	verifier := "verifier-verifier-verifier-verifier-verifier-1234"
	q := url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {"https://" + host + "/cb"},
		"scope": {scope}, "state": {"st"}, "nonce": {nonce}, "resource": {"https://files.example.com/mcp"},
		"code_challenge": {crypto.CodeChallenge(verifier)}, "code_challenge_method": {"S256"},
	}
	code, hdr, b := h.get("/oauth/authorize?"+q.Encode(), true, nil)
	if code != http.StatusFound {
		h.t.Fatalf("authorize: %d %s", code, b)
	}
	loc, _ := url.Parse(hdr.Get("Location"))
	authCode := loc.Query().Get("code")
	if authCode == "" {
		h.t.Fatalf("no code in %s", loc)
	}
	status, body := h.postForm("/oauth/token", url.Values{
		"grant_type": {"authorization_code"}, "client_id": {clientID}, "code": {authCode},
		"code_verifier": {verifier}, "redirect_uri": {"https://" + host + "/cb"},
	})
	if status != http.StatusOK {
		h.t.Fatalf("token: %d %s", status, body)
	}
	var out map[string]any
	_ = json.Unmarshal(body, &out)
	return out
}

func decodeJWT(t *testing.T, tok string) (header, claims map[string]any) {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", tok)
	}
	dec := func(s string) map[string]any {
		b, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	return dec(parts[0]), dec(parts[1])
}

// verifyAgainstJWKS checks the EdDSA signature of tok with the served JWKS.
func (h *oidcHarness) verifyAgainstJWKS(tok string) {
	h.t.Helper()
	hdr, _ := decodeJWT(h.t, tok)
	_, _, body := h.get("/oauth/jwks", false, nil)
	var set struct {
		Keys []struct {
			Kid string `json:"kid"`
			X   string `json:"x"`
		} `json:"keys"`
	}
	_ = json.Unmarshal(body, &set)
	parts := strings.Split(tok, ".")
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	for _, k := range set.Keys {
		if k.Kid != hdr["kid"] {
			continue
		}
		x, _ := base64.RawURLEncoding.DecodeString(k.X)
		if !ed25519.Verify(ed25519.PublicKey(x), []byte(parts[0]+"."+parts[1]), sig) {
			h.t.Fatal("signature does not verify")
		}
		return
	}
	h.t.Fatalf("kid %v not in JWKS", hdr["kid"])
}

func TestOIDCIDTokenUserinfoAndLogout(t *testing.T) {
	h := newOIDCHarness(t, &theauth.OIDCConfig{
		PairwiseSalt:         []byte("0123456789abcdef-pairwise-salt"),
		AllowPrivateNetworks: true,
	})
	clientID := h.registerRP("rp.example.com")
	tok := h.login(clientID, "rp.example.com", "openid profile email files.read", "n-0S6_WzA2Mj")

	idToken, _ := tok["id_token"].(string)
	if idToken == "" {
		t.Fatalf("no id_token in %v", tok)
	}
	h.verifyAgainstJWKS(idToken)
	hdr, claims := decodeJWT(t, idToken)
	if hdr["typ"] != "JWT" || hdr["alg"] != "EdDSA" {
		t.Fatalf("header: %v", hdr)
	}
	if claims["iss"] != "https://auth.example.com" || claims["aud"] != clientID || claims["nonce"] != "n-0S6_WzA2Mj" {
		t.Fatalf("claims: %v", claims)
	}
	// at_hash: left half of SHA-512 for EdDSA (Ed25519).
	sum := sha512.Sum512([]byte(tok["access_token"].(string)))
	if want := base64.RawURLEncoding.EncodeToString(sum[:32]); claims["at_hash"] != want {
		t.Fatalf("at_hash %v, want %s", claims["at_hash"], want)
	}
	sub, _ := claims["sub"].(string)
	if sub == "" || sub == h.user.ID.String() {
		t.Fatalf("pairwise sub expected, got %q", sub)
	}
	sid, _ := claims["sid"].(string)
	if sid == "" {
		t.Fatal("sid missing")
	}

	// userinfo
	code, _, body := h.get("/oauth/userinfo", false, map[string]string{"Authorization": "Bearer " + tok["access_token"].(string)})
	if code != http.StatusOK {
		t.Fatalf("userinfo: %d %s", code, body)
	}
	var info map[string]any
	_ = json.Unmarshal(body, &info)
	if info["sub"] != sub || info["email"] != "ada@example.com" || info["email_verified"] != true || info["name"] != "Ada Lovelace" {
		t.Fatalf("userinfo: %v", info)
	}
	if code, hdr, _ := h.get("/oauth/userinfo", false, map[string]string{"Authorization": "Bearer nope.nope.nope"}); code != http.StatusUnauthorized ||
		!strings.Contains(hdr.Get("WWW-Authenticate"), "invalid_token") {
		t.Fatalf("bad token: %d %v", code, hdr)
	}
	if code, _, _ := h.get("/oauth/userinfo", false, nil); code != http.StatusUnauthorized {
		t.Fatalf("no token: %d", code)
	}

	// refresh keeps the sid and drops the nonce
	status, rb := h.postForm("/oauth/token", url.Values{
		"grant_type": {"refresh_token"}, "client_id": {clientID}, "refresh_token": {tok["refresh_token"].(string)},
	})
	if status != http.StatusOK {
		t.Fatalf("refresh: %d %s", status, rb)
	}
	var refreshed map[string]any
	_ = json.Unmarshal(rb, &refreshed)
	_, rc := decodeJWT(t, refreshed["id_token"].(string))
	if rc["sid"] != sid || rc["nonce"] != nil || rc["sub"] != sub {
		t.Fatalf("refreshed id token: %v", rc)
	}

	// unregistered post logout redirect is refused and the session survives
	q := url.Values{"id_token_hint": {idToken}, "post_logout_redirect_uri": {"https://evil.example.com/"}}
	if code, _, _ := h.get("/oauth/end_session?"+q.Encode(), true, nil); code != http.StatusBadRequest {
		t.Fatalf("unregistered redirect: %d", code)
	}
	if s, err := h.store.SessionByID(context.Background(), h.session.ID); err != nil || s.RevokedAt != nil {
		t.Fatalf("session must survive a refused logout: %v %+v", err, s)
	}

	// RP-initiated logout
	q = url.Values{"id_token_hint": {idToken}, "post_logout_redirect_uri": {"https://rp.example.com/bye"}, "state": {"xyz"}}
	code, hdr2, body := h.get("/oauth/end_session?"+q.Encode(), true, nil)
	if code != http.StatusFound {
		t.Fatalf("end_session: %d %s", code, body)
	}
	if loc := hdr2.Get("Location"); loc != "https://rp.example.com/bye?state=xyz" {
		t.Fatalf("redirect: %s", loc)
	}
	if s, err := h.store.SessionByID(context.Background(), h.session.ID); err != nil || s.RevokedAt == nil {
		t.Fatalf("session not revoked: %v %+v", err, s)
	}
	select {
	case <-h.logoutC:
	case <-time.After(5 * time.Second):
		t.Fatal("no back-channel logout delivery")
	}
	h.mu.Lock()
	lt := h.logouts[0]
	h.mu.Unlock()
	h.verifyAgainstJWKS(lt)
	lh, lc := decodeJWT(t, lt)
	events, _ := lc["events"].(map[string]any)
	if lh["typ"] != "logout+jwt" || lc["aud"] != clientID || lc["sub"] != sub || lc["sid"] != sid || lc["nonce"] != nil {
		t.Fatalf("logout token: %v %v", lh, lc)
	}
	if _, ok := events["http://schemas.openid.net/event/backchannel-logout"]; !ok {
		t.Fatalf("events: %v", lc["events"])
	}
}

func TestOIDCPairwiseSubjectsDifferPerSector(t *testing.T) {
	h := newOIDCHarness(t, &theauth.OIDCConfig{PairwiseSalt: []byte("0123456789abcdef-pairwise-salt"), AllowPrivateNetworks: true})
	a := h.registerRP("a.example.com")
	b := h.registerRP("b.example.com")
	subA := idTokenSub(t, h.login(a, "a.example.com", "openid", "n1"))
	subB := idTokenSub(t, h.login(b, "b.example.com", "openid", "n2"))
	if subA == subB || subA == h.user.ID.String() || subB == h.user.ID.String() {
		t.Fatalf("pairwise subjects must differ per sector: %q %q", subA, subB)
	}
	// stable for the same sector
	if again := idTokenSub(t, h.login(a, "a.example.com", "openid", "n3")); again != subA {
		t.Fatalf("pairwise sub not stable: %q vs %q", again, subA)
	}
}

func idTokenSub(t *testing.T, tok map[string]any) string {
	t.Helper()
	_, c := decodeJWT(t, tok["id_token"].(string))
	return c["sub"].(string)
}

func TestOIDCPublicClientAndDiscovery(t *testing.T) {
	h := newOIDCHarness(t, &theauth.OIDCConfig{})
	clientID := h.register(`{"client_name":"RP","redirect_uris":["https://rp.example.com/cb"],"token_endpoint_auth_method":"none"}`)
	tok := h.login(clientID, "rp.example.com", "openid files.read", "")
	_, c := decodeJWT(t, tok["id_token"].(string))
	if c["sub"] != h.user.ID.String() {
		t.Fatalf("public sub: %v", c["sub"])
	}
	if _, ok := c["nonce"]; ok {
		t.Fatal("nonce must be absent when the request had none")
	}
	// scope without openid yields no id_token
	plain := h.login(clientID, "rp.example.com", "files.read", "")
	if _, ok := plain["id_token"]; ok {
		t.Fatal("id_token without openid scope")
	}
	// userinfo needs the openid scope
	code, _, _ := h.get("/oauth/userinfo", false, map[string]string{"Authorization": "Bearer " + plain["access_token"].(string)})
	if code != http.StatusForbidden {
		t.Fatalf("userinfo without openid: %d", code)
	}

	_, _, body := h.get("/.well-known/openid-configuration", false, nil)
	var doc map[string]any
	_ = json.Unmarshal(body, &doc)
	for _, k := range []string{"userinfo_endpoint", "end_session_endpoint", "subject_types_supported",
		"id_token_signing_alg_values_supported", "backchannel_logout_supported", "claims_supported"} {
		if doc[k] == nil {
			t.Errorf("discovery lacks %s: %s", k, body)
		}
	}
	if doc["userinfo_endpoint"] != "https://auth.example.com/oauth/userinfo" {
		t.Errorf("userinfo_endpoint: %v", doc["userinfo_endpoint"])
	}
	if st, _ := doc["subject_types_supported"].([]any); len(st) != 1 || st[0] != "public" {
		t.Errorf("subject types without a salt: %v", doc["subject_types_supported"])
	}
}

func TestOIDCDisabledByDefault(t *testing.T) {
	h := newOIDCHarness(t, nil)
	clientID := h.register(`{"client_name":"RP","redirect_uris":["https://rp.example.com/cb"],"token_endpoint_auth_method":"none"}`)
	tok := h.login(clientID, "rp.example.com", "files.read", "")
	if _, ok := tok["id_token"]; ok {
		t.Fatal("id_token without OIDC config")
	}
	if code, _, _ := h.get("/oauth/userinfo", false, nil); code != http.StatusNotFound && code != http.StatusMethodNotAllowed {
		t.Fatalf("userinfo mounted without OIDC: %d", code)
	}
}

func TestOIDCRegistrationValidation(t *testing.T) {
	h := newOIDCHarness(t, &theauth.OIDCConfig{AllowPrivateNetworks: true})
	post := func(body string) int {
		req, _ := http.NewRequest(http.MethodPost, h.srv.URL+"/oauth/register", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer static-token")
		code, _, _ := h.send(req)
		return code
	}
	cases := map[string]string{
		"pairwise without salt":     `{"redirect_uris":["https://a.example.com/cb"],"token_endpoint_auth_method":"none","subject_type":"pairwise"}`,
		"unknown subject type":      `{"redirect_uris":["https://a.example.com/cb"],"token_endpoint_auth_method":"none","subject_type":"weird"}`,
		"bad post logout uri":       `{"redirect_uris":["https://a.example.com/cb"],"token_endpoint_auth_method":"none","post_logout_redirect_uris":["javascript:alert(1)"]}`,
		"backchannel with fragment": `{"redirect_uris":["https://a.example.com/cb"],"token_endpoint_auth_method":"none","backchannel_logout_uri":"https://a.example.com/x#f"}`,
	}
	for name, body := range cases {
		if code := post(body); code != http.StatusBadRequest {
			t.Errorf("%s: got %d, want 400", name, code)
		}
	}
	if code := post(`{"redirect_uris":["https://a.example.com/cb"],"token_endpoint_auth_method":"none","backchannel_logout_uri":"https://a.example.com/logout"}`); code != http.StatusCreated {
		t.Errorf("valid backchannel registration: %d", code)
	}
}

func TestOIDCConfigValidation(t *testing.T) {
	store := memory.New()
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	_, err := theauth.New(theauth.Config{
		Storage: store, BaseURL: "https://auth.example.com", EncryptionKey: key,
		AuthorizationServer: &theauth.AuthorizationServerConfig{
			Issuer: "https://auth.example.com", DisableRotation: true,
			Resources: []theauth.ProtectedResource{{Identifier: "https://files.example.com/mcp"}},
			OIDC:      &theauth.OIDCConfig{DefaultSubjectType: "pairwise"},
		},
	})
	if err == nil {
		t.Fatal("pairwise default without a salt must be refused")
	}
}
