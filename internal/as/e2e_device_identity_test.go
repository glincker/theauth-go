package as_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/internal/ulid"
	"github.com/glincker/theauth-go/v2/storage/memory"
	"github.com/go-chi/chi/v5"
)

// e2e_device_identity_test.go: constrained device enrollment (join token plus
// signed challenge) and the RFC 7523 device assertion grant, through the real
// AS handlers.

const (
	devIssuer   = "https://auth.example.com"
	devTokenURL = devIssuer + "/oauth/token"
	devResource = "https://iot.example.com/api"
)

type iotHarness struct {
	a      *theauth.TheAuth
	srv    *httptest.Server
	org    theauth.ULID
	client theauth.RegisteredClient
}

func newIoTHarness(t *testing.T, cfg *theauth.DeviceTokensConfig) *iotHarness {
	t.Helper()
	if cfg == nil {
		cfg = &theauth.DeviceTokensConfig{}
	}
	enc := make([]byte, 32)
	if _, err := rand.Read(enc); err != nil {
		t.Fatal(err)
	}
	a, err := theauth.New(theauth.Config{
		Storage:       memory.New(),
		BaseURL:       devIssuer,
		EncryptionKey: enc,
		AuthorizationServer: &theauth.AuthorizationServerConfig{
			Issuer: devIssuer,
			Resources: []theauth.ProtectedResource{
				{Identifier: devResource, Scopes: []string{"telemetry:write", "config:read", "admin"}},
			},
			RegistrationTokens: []string{"initial-access-token"},
			DisableRotation:    true,
			DPoP:               &theauth.DPoPConfig{},
			DeviceTokens:       cfg,
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(a.Close)
	r := chi.NewRouter()
	a.Mount(r)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return &iotHarness{a: a, srv: srv, org: ulid.New(), client: registerTestClient(t, srv)}
}

// devKey is a device keypair that can sign JWS compact tokens.
type devKey struct {
	jwk  map[string]string
	alg  string
	sign func(msg []byte) []byte
}

func newES256DevKey(t *testing.T) devKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var x, y [32]byte
	priv.X.FillBytes(x[:])
	priv.Y.FillBytes(y[:])
	return devKey{
		jwk: map[string]string{
			"kty": "EC", "crv": "P-256",
			"x": base64.RawURLEncoding.EncodeToString(x[:]), "y": base64.RawURLEncoding.EncodeToString(y[:]),
		},
		alg: "ES256",
		sign: func(msg []byte) []byte {
			d := sha256.Sum256(msg)
			r, s, err := ecdsa.Sign(rand.Reader, priv, d[:])
			if err != nil {
				t.Fatal(err)
			}
			sig := make([]byte, 64)
			r.FillBytes(sig[:32])
			s.FillBytes(sig[32:])
			return sig
		},
	}
}

func newEd25519DevKey(t *testing.T) devKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return devKey{
		jwk: map[string]string{"kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(pub)},
		alg: "EdDSA",
		sign: func(msg []byte) []byte {
			return ed25519.Sign(priv, msg)
		},
	}
}

func (k devKey) jwkJSON() json.RawMessage {
	b, _ := json.Marshal(k.jwk)
	return b
}

func (k devKey) jws(t *testing.T, typ string, claims map[string]any) string {
	t.Helper()
	h, _ := json.Marshal(map[string]any{"alg": k.alg, "typ": typ})
	p, _ := json.Marshal(claims)
	in := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(p)
	return in + "." + base64.RawURLEncoding.EncodeToString(k.sign([]byte(in)))
}

func postJSON(t *testing.T, url string, body any) (int, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(body)
	resp, err := http.Post(url, "application/json", strings.NewReader(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var m map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&m)
	return resp.StatusCode, m
}

func (h *iotHarness) mint(t *testing.T, in theauth.CreateDeviceJoinTokenInput) (theauth.DeviceJoinToken, string) {
	t.Helper()
	if in.OrganizationID == nil {
		in.OrganizationID = &h.org
	}
	if len(in.Scopes) == 0 {
		in.Scopes = []string{"telemetry:write", "config:read"}
	}
	tok, secret, err := h.a.CreateDeviceJoinToken(context.Background(), in)
	if err != nil {
		t.Fatalf("CreateDeviceJoinToken: %v", err)
	}
	return tok, secret
}

// challenge requests an enrollment challenge and returns the nonce JWT.
func (h *iotHarness) challenge(t *testing.T, joinToken string, key devKey) (int, string) {
	t.Helper()
	code, body := postJSON(t, h.srv.URL+"/oauth/devices/challenge", map[string]any{"join_token": joinToken, "jwk": key.jwkJSON()})
	ch, _ := body["challenge"].(string)
	return code, ch
}

// nonceOf reads the jti (the nonce) out of the challenge JWT.
func nonceOf(t *testing.T, challenge string) string {
	t.Helper()
	parts := strings.Split(challenge, ".")
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var c struct {
		Jti string `json:"jti"`
	}
	_ = json.Unmarshal(raw, &c)
	return c.Jti
}

func (h *iotHarness) proof(t *testing.T, key devKey, challenge string) string {
	t.Helper()
	now := time.Now()
	return key.jws(t, "device-enroll+jwt", map[string]any{
		"aud": devIssuer, "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(), "nonce": nonceOf(t, challenge),
	})
}

// enroll runs the full challenge and proof exchange and returns the status
// and body of the enroll call.
func (h *iotHarness) enroll(t *testing.T, joinToken string, key devKey) (int, map[string]any) {
	t.Helper()
	code, ch := h.challenge(t, joinToken, key)
	if code != http.StatusOK {
		return code, nil
	}
	return postJSON(t, h.srv.URL+"/oauth/devices/enroll", map[string]any{
		"join_token": joinToken, "jwk": key.jwkJSON(), "challenge": ch, "proof": h.proof(t, key, ch),
	})
}

func (h *iotHarness) enrolled(t *testing.T, key devKey, in theauth.CreateDeviceJoinTokenInput) string {
	t.Helper()
	_, secret := h.mint(t, in)
	code, body := h.enroll(t, secret, key)
	if code != http.StatusCreated {
		t.Fatalf("enroll: %d %v", code, body)
	}
	return body["device_id"].(string)
}

type assertionOpts struct {
	aud      string
	iat, exp time.Time
	jti      string
	iss, sub string
}

func (h *iotHarness) assertion(t *testing.T, key devKey, deviceID string, mod func(*assertionOpts)) string {
	t.Helper()
	now := time.Now()
	o := assertionOpts{aud: devTokenURL, iat: now, exp: now.Add(time.Minute), jti: ulid.New().String(), iss: deviceID, sub: deviceID}
	if mod != nil {
		mod(&o)
	}
	return key.jws(t, "JWT", map[string]any{
		"iss": o.iss, "sub": o.sub, "aud": o.aud, "iat": o.iat.Unix(), "exp": o.exp.Unix(), "jti": o.jti,
	})
}

func (h *iotHarness) token(t *testing.T, assertion string, form url.Values, dpop string) (int, map[string]any) {
	t.Helper()
	v := url.Values{}
	v.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	v.Set("assertion", assertion)
	for k, vals := range form {
		v[k] = vals
	}
	req, _ := http.NewRequest(http.MethodPost, h.srv.URL+"/oauth/token", strings.NewReader(v.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if dpop != "" {
		req.Header.Set("DPoP", dpop)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return resp.StatusCode, m
}

func (h *iotHarness) introspect(t *testing.T, token string) map[string]any {
	t.Helper()
	form := url.Values{"token": {token}, "client_id": {h.client.ClientID}, "client_secret": {h.client.ClientSecret}}
	resp, err := http.PostForm(h.srv.URL+"/oauth/introspect", form)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var m map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&m)
	return m
}

func jwtClaims(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a jwt: %q", token)
	}
	raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return m
}

func TestDeviceEnrollmentAndTokenHappyPath(t *testing.T) {
	for name, mk := range map[string]func(*testing.T) devKey{"ES256": newES256DevKey, "Ed25519": newEd25519DevKey} {
		t.Run(name, func(t *testing.T) {
			h := newIoTHarness(t, nil)
			key := mk(t)
			spiffe := "spiffe://example.org/sensor/" + name
			tok, secret := h.mint(t, theauth.CreateDeviceJoinTokenInput{Name: "boiler sensor", SPIFFEID: spiffe})
			if !strings.HasPrefix(secret, "dj_") || tok.Prefix == "" {
				t.Fatalf("join token: %q %+v", secret, tok)
			}
			code, body := h.enroll(t, secret, key)
			if code != http.StatusCreated {
				t.Fatalf("enroll: %d %v", code, body)
			}
			devID := body["device_id"].(string)
			if body["subject"] != spiffe || body["name"] != "boiler sensor" {
				t.Fatalf("enroll body: %v", body)
			}
			devs, err := h.a.ListDevices(context.Background(), &h.org)
			if err != nil || len(devs) != 1 || devs[0].ID.String() != devID || devs[0].Attestation != theauth.DeviceAttestationJoinToken {
				t.Fatalf("ListDevices: %+v %v", devs, err)
			}

			code, tr := h.token(t, h.assertion(t, key, devID, nil), nil, "")
			if code != http.StatusOK {
				t.Fatalf("token: %d %v", code, tr)
			}
			if tr["token_type"] != "Bearer" || tr["expires_in"] != float64(600) || tr["refresh_token"] != nil {
				t.Fatalf("response: %v", tr)
			}
			claims := jwtClaims(t, tr["access_token"].(string))
			if claims["sub"] != spiffe || claims["device_id"] != devID || claims["aud"] != devResource ||
				claims["scope"] != "telemetry:write config:read" || claims["cnf"] != nil {
				t.Fatalf("claims: %v", claims)
			}
			exp, iat := claims["exp"].(float64), claims["iat"].(float64)
			if exp-iat != 600 {
				t.Fatalf("lifetime %v, want 600s", exp-iat)
			}
			if in := h.introspect(t, tr["access_token"].(string)); in["active"] != true || in["device_id"] != devID {
				t.Fatalf("introspect: %v", in)
			}
			got, _ := h.a.ListDevices(context.Background(), &h.org)
			if got[0].LastSeenAt == nil {
				t.Fatal("last_seen_at not stamped")
			}
		})
	}
}

func TestDeviceTokenSubjectFallsBackToDeviceID(t *testing.T) {
	h := newIoTHarness(t, &theauth.DeviceTokensConfig{AccessTokenTTL: 2 * time.Minute})
	key := newES256DevKey(t)
	devID := h.enrolled(t, key, theauth.CreateDeviceJoinTokenInput{Name: "no spiffe"})
	code, tr := h.token(t, h.assertion(t, key, devID, nil), nil, "")
	if code != http.StatusOK {
		t.Fatalf("token: %d %v", code, tr)
	}
	if tr["expires_in"] != float64(120) {
		t.Fatalf("configured ttl not applied: %v", tr["expires_in"])
	}
	if sub := jwtClaims(t, tr["access_token"].(string))["sub"]; sub != "device:"+devID {
		t.Fatalf("sub = %v", sub)
	}
}

func TestDeviceJoinTokenReplay(t *testing.T) {
	h := newIoTHarness(t, nil)
	_, secret := h.mint(t, theauth.CreateDeviceJoinTokenInput{SPIFFEID: "spiffe://example.org/replay"})
	first, second := newES256DevKey(t), newES256DevKey(t)

	// A second device grabs a challenge while the token is still unspent.
	code, staleChallenge := h.challenge(t, secret, second)
	if code != http.StatusOK {
		t.Fatalf("second challenge: %d", code)
	}
	if code, body := h.enroll(t, secret, first); code != http.StatusCreated {
		t.Fatalf("first enroll: %d %v", code, body)
	}
	// The spent token is refused at both steps.
	if code, _ := h.challenge(t, secret, second); code != http.StatusBadRequest {
		t.Fatalf("challenge with spent token: %d", code)
	}
	code, body := postJSON(t, h.srv.URL+"/oauth/devices/enroll", map[string]any{
		"join_token": secret, "jwk": second.jwkJSON(), "challenge": staleChallenge, "proof": h.proof(t, second, staleChallenge),
	})
	if code != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Fatalf("replayed enroll: %d %v", code, body)
	}
	if devs, _ := h.a.ListDevices(context.Background(), &h.org); len(devs) != 1 {
		t.Fatalf("devices registered = %d, want 1", len(devs))
	}
}

func TestDeviceEnrollmentWrongKeyProof(t *testing.T) {
	h := newIoTHarness(t, nil)
	_, secret := h.mint(t, theauth.CreateDeviceJoinTokenInput{})
	claimed, attacker := newES256DevKey(t), newES256DevKey(t)
	code, ch := h.challenge(t, secret, claimed)
	if code != http.StatusOK {
		t.Fatalf("challenge: %d", code)
	}
	// Presents the claimed public key but signs the nonce with another key.
	code, body := postJSON(t, h.srv.URL+"/oauth/devices/enroll", map[string]any{
		"join_token": secret, "jwk": claimed.jwkJSON(), "challenge": ch, "proof": h.proof(t, attacker, ch),
	})
	if code != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Fatalf("wrong key proof: %d %v", code, body)
	}
	// A challenge issued for one key cannot enroll a different key.
	code, _ = postJSON(t, h.srv.URL+"/oauth/devices/enroll", map[string]any{
		"join_token": secret, "jwk": attacker.jwkJSON(), "challenge": ch, "proof": h.proof(t, attacker, ch),
	})
	if code != http.StatusBadRequest {
		t.Fatalf("challenge reuse for another key: %d", code)
	}
	// Failed attempts must not burn the token.
	if code, body := h.enroll(t, secret, claimed); code != http.StatusCreated {
		t.Fatalf("legitimate enroll after failures: %d %v", code, body)
	}
}

func TestDeviceEnrollmentRejectsPrivateKeyAndRevokedJoinToken(t *testing.T) {
	h := newIoTHarness(t, nil)
	tok, secret := h.mint(t, theauth.CreateDeviceJoinTokenInput{})
	key := newES256DevKey(t)
	withD := key.jwk
	withD["d"] = "AAAA"
	b, _ := json.Marshal(withD)
	if code, _ := postJSON(t, h.srv.URL+"/oauth/devices/challenge", map[string]any{"join_token": secret, "jwk": json.RawMessage(b)}); code != http.StatusBadRequest {
		t.Fatalf("private key material accepted: %d", code)
	}
	delete(key.jwk, "d")
	if err := h.a.RevokeDeviceJoinToken(context.Background(), tok.ID); err != nil {
		t.Fatal(err)
	}
	if code, _ := h.challenge(t, secret, key); code != http.StatusBadRequest {
		t.Fatalf("revoked join token accepted: %d", code)
	}
}

func TestDeviceAssertionValidation(t *testing.T) {
	h := newIoTHarness(t, nil)
	key := newES256DevKey(t)
	devID := h.enrolled(t, key, theauth.CreateDeviceJoinTokenInput{SPIFFEID: "spiffe://example.org/validate"})
	other := newES256DevKey(t)
	now := time.Now()

	cases := map[string]string{
		"expired": h.assertion(t, key, devID, func(o *assertionOpts) {
			o.iat, o.exp = now.Add(-10*time.Minute), now.Add(-5*time.Minute)
		}),
		"lifetime too long": h.assertion(t, key, devID, func(o *assertionOpts) { o.exp = now.Add(time.Hour) }),
		"issued in the future": h.assertion(t, key, devID, func(o *assertionOpts) {
			o.iat, o.exp = now.Add(time.Hour), now.Add(time.Hour+time.Minute)
		}),
		"wrong audience":        h.assertion(t, key, devID, func(o *assertionOpts) { o.aud = devIssuer }),
		"missing jti":           h.assertion(t, key, devID, func(o *assertionOpts) { o.jti = "" }),
		"short jti":             h.assertion(t, key, devID, func(o *assertionOpts) { o.jti = "0123456789abcde" }),
		"signed by another key": h.assertion(t, other, devID, nil),
	}
	for name, a := range cases {
		code, body := h.token(t, a, nil, "")
		if code != http.StatusBadRequest || body["error"] != "invalid_grant" {
			t.Errorf("%s: %d %v", name, code, body)
		}
	}
	// iss and sub must both be the device id.
	a := h.assertion(t, key, devID, func(o *assertionOpts) { o.sub = "someone-else" })
	if code, _ := h.token(t, a, nil, ""); code == http.StatusOK {
		t.Error("sub mismatch accepted")
	}
	if code, tr := h.token(t, h.assertion(t, key, devID, nil), nil, ""); code != http.StatusOK {
		t.Fatalf("valid assertion refused after failures: %d %v", code, tr)
	}
}

func TestDeviceAssertionJTIReplay(t *testing.T) {
	h := newIoTHarness(t, nil)
	key := newES256DevKey(t)
	devID := h.enrolled(t, key, theauth.CreateDeviceJoinTokenInput{})
	a := h.assertion(t, key, devID, nil)
	if code, tr := h.token(t, a, nil, ""); code != http.StatusOK {
		t.Fatalf("first use: %d %v", code, tr)
	}
	code, body := h.token(t, a, nil, "")
	if code != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Fatalf("replayed assertion: %d %v", code, body)
	}
}

func TestDeviceScopeAndResourceNarrowing(t *testing.T) {
	h := newIoTHarness(t, nil)
	key := newES256DevKey(t)
	devID := h.enrolled(t, key, theauth.CreateDeviceJoinTokenInput{Scopes: []string{"telemetry:write"}})

	code, body := h.token(t, h.assertion(t, key, devID, nil), url.Values{"scope": {"admin"}}, "")
	if code != http.StatusBadRequest || body["error"] != "invalid_scope" {
		t.Fatalf("scope beyond the device grant: %d %v", code, body)
	}
	code, body = h.token(t, h.assertion(t, key, devID, nil), url.Values{"resource": {"https://other.example.com"}}, "")
	if code != http.StatusBadRequest || body["error"] != "invalid_target" {
		t.Fatalf("unknown resource: %d %v", code, body)
	}
	code, body = h.token(t, h.assertion(t, key, devID, nil), url.Values{"scope": {"telemetry:write"}, "resource": {devResource}}, "")
	if code != http.StatusOK || body["scope"] != "telemetry:write" {
		t.Fatalf("narrowed request: %d %v", code, body)
	}
}

func TestDeviceRevocation(t *testing.T) {
	h := newIoTHarness(t, nil)
	key := newES256DevKey(t)
	devID := h.enrolled(t, key, theauth.CreateDeviceJoinTokenInput{SPIFFEID: "spiffe://example.org/revoke"})
	code, tr := h.token(t, h.assertion(t, key, devID, nil), nil, "")
	if code != http.StatusOK {
		t.Fatalf("token: %d %v", code, tr)
	}
	access := tr["access_token"].(string)
	// Prime the introspection cache so revocation has to beat it.
	if in := h.introspect(t, access); in["active"] != true {
		t.Fatalf("pre-revoke introspect: %v", in)
	}

	var id theauth.ULID
	if err := id.UnmarshalText([]byte(devID)); err != nil {
		t.Fatal(err)
	}
	if err := h.a.RevokeDevice(context.Background(), id); err != nil {
		t.Fatalf("RevokeDevice: %v", err)
	}
	if err := h.a.RevokeDevice(context.Background(), id); err != nil {
		t.Fatalf("second RevokeDevice: %v", err)
	}
	code, body := h.token(t, h.assertion(t, key, devID, nil), nil, "")
	if code != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Fatalf("assertion after revoke: %d %v", code, body)
	}
	if in := h.introspect(t, access); in["active"] != false {
		t.Fatalf("token still active after revoke: %v", in)
	}
	devs, _ := h.a.ListDevices(context.Background(), &h.org)
	if len(devs) != 1 || devs[0].Status != theauth.DeviceStatusRevoked || devs[0].RevokedAt == nil {
		t.Fatalf("device record: %+v", devs)
	}
}

func TestDeviceTokenDPoPBinding(t *testing.T) {
	h := newIoTHarness(t, nil)
	key := newES256DevKey(t)
	devID := h.enrolled(t, key, theauth.CreateDeviceJoinTokenInput{})
	dpopPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// A bad proof is refused without spending the assertion.
	a := h.assertion(t, key, devID, nil)
	badPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	stale := makeDPoPProof(t, badPriv, "POST", devTokenURL, "", time.Now().Add(-time.Hour))
	code, body := h.token(t, a, nil, stale)
	if code != http.StatusBadRequest || body["error"] != "invalid_dpop_proof" {
		t.Fatalf("stale proof: %d %v", code, body)
	}

	proof := makeDPoPProof(t, dpopPriv, "POST", devTokenURL, "", time.Now())
	code, tr := h.token(t, a, nil, proof)
	if code != http.StatusOK {
		t.Fatalf("dpop token: %d %v", code, tr)
	}
	if tr["token_type"] != "DPoP" {
		t.Fatalf("token_type = %v", tr["token_type"])
	}
	cnf, _ := jwtClaims(t, tr["access_token"].(string))["cnf"].(map[string]any)
	if cnf["jkt"] != jwkThumbprintES256(t, dpopPriv) {
		t.Fatalf("cnf = %v", cnf)
	}
	if in := h.introspect(t, tr["access_token"].(string)); in["token_type"] != "DPoP" {
		t.Fatalf("introspect: %v", in)
	}

	// Without a proof the same device still gets a plain bearer token.
	code, tr = h.token(t, h.assertion(t, key, devID, nil), nil, "")
	if code != http.StatusOK || tr["token_type"] != "Bearer" {
		t.Fatalf("bearer token: %d %v", code, tr)
	}
}
