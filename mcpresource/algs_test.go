package mcpresource

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// testKeys holds one key pair per supported algorithm.
type testKeys struct {
	ed    ed25519.PrivateKey
	ec    *ecdsa.PrivateKey
	rsa2k *rsa.PrivateKey
}

func newTestKeys(t *testing.T) *testKeys {
	t.Helper()
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa: %v", err)
	}
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	return &testKeys{ed: ed, ec: ec, rsa2k: rk}
}

func (k *testKeys) jwk(kid, alg string) map[string]any {
	switch alg {
	case "EdDSA":
		return map[string]any{"kty": "OKP", "crv": "Ed25519", "kid": kid, "use": "sig",
			"x": base64.RawURLEncoding.EncodeToString(k.ed.Public().(ed25519.PublicKey))}
	case "ES256":
		return map[string]any{"kty": "EC", "crv": "P-256", "kid": kid, "use": "sig",
			"x": base64.RawURLEncoding.EncodeToString(k.ec.X.FillBytes(make([]byte, 32))),
			"y": base64.RawURLEncoding.EncodeToString(k.ec.Y.FillBytes(make([]byte, 32)))}
	default:
		return map[string]any{"kty": "RSA", "kid": kid, "use": "sig",
			"n": base64.RawURLEncoding.EncodeToString(k.rsa2k.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.rsa2k.E)).Bytes())}
	}
}

// signAlg mints a JWT with the header alg alg, signed by the private key that
// belongs to signWith (which may differ from alg to craft confusion tokens).
func (k *testKeys) signAlg(t *testing.T, alg, signWith, kid string, claims map[string]any) string {
	t.Helper()
	hb, _ := json.Marshal(map[string]string{"alg": alg, "typ": "at+jwt", "kid": kid})
	cb, _ := json.Marshal(claims)
	in := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(cb)
	var sig []byte
	switch signWith {
	case "EdDSA":
		sig = ed25519.Sign(k.ed, []byte(in))
	case "ES256":
		h := sha256.Sum256([]byte(in))
		r, s, err := ecdsa.Sign(rand.Reader, k.ec, h[:])
		if err != nil {
			t.Fatalf("ecdsa sign: %v", err)
		}
		sig = append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	case "RS256":
		h := sha256.Sum256([]byte(in))
		var err error
		sig, err = rsa.SignPKCS1v15(rand.Reader, k.rsa2k, crypto.SHA256, h[:])
		if err != nil {
			t.Fatalf("rsa sign: %v", err)
		}
	case "HS256":
		m := hmac.New(sha256.New, []byte("secret"))
		m.Write([]byte(in))
		sig = m.Sum(nil)
	case "none":
		sig = nil
	}
	return in + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func algClaims(aud any) map[string]any {
	return map[string]any{"iss": "i", "sub": "u", "aud": aud, "exp": time.Now().Add(time.Hour).Unix(), "jti": "j"}
}

func (k *testKeys) resolver() keyResolver {
	return func(kid, _ string) (crypto.PublicKey, error) {
		switch kid {
		case "ed":
			return k.ed.Public(), nil
		case "ec":
			return &k.ec.PublicKey, nil
		case "rsa":
			return &k.rsa2k.PublicKey, nil
		}
		return nil, errUnknownKidForTest
	}
}

var errUnknownKidForTest = newError("unknown kid")

func TestVerifyJWTAlgorithms(t *testing.T) {
	k := newTestKeys(t)
	tests := []struct {
		name     string
		alg      string
		signWith string
		kid      string
		wantErr  bool
	}{
		{"EdDSA accepted", "EdDSA", "EdDSA", "ed", false},
		{"ES256 accepted", "ES256", "ES256", "ec", false},
		{"RS256 accepted", "RS256", "RS256", "rsa", false},
		{"ES256 header with EdDSA key rejected", "ES256", "ES256", "ed", true},
		{"RS256 header with EC key rejected", "RS256", "RS256", "ec", true},
		{"EdDSA header with RSA key rejected", "EdDSA", "EdDSA", "rsa", true},
		{"EdDSA header over ES256 key rejected", "EdDSA", "EdDSA", "ec", true},
		{"alg none rejected", "none", "none", "ed", true},
		{"HS256 rejected", "HS256", "HS256", "ed", true},
		{"ES256 sig under RS256 header rejected", "RS256", "ES256", "rsa", true},
		{"RS256 sig under ES256 header rejected", "ES256", "RS256", "ec", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tok := k.signAlg(t, tc.alg, tc.signWith, tc.kid, algClaims("a"))
			c, err := verifyJWT(tok, "a", k.resolver(), time.Now(), time.Minute, false)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tc.wantErr)
			}
			if err == nil && c.Sub != "u" {
				t.Fatalf("sub=%q", c.Sub)
			}
		})
	}
}

func TestVerifyJWTRejectsSmallRSAKey(t *testing.T) {
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	k := &testKeys{rsa2k: small}
	tok := k.signAlg(t, "RS256", "RS256", "rsa", algClaims("a"))
	resolve := func(string, string) (crypto.PublicKey, error) { return &small.PublicKey, nil }
	if _, err := verifyJWT(tok, "a", resolve, time.Now(), time.Minute, false); err == nil {
		t.Fatal("expected 1024 bit RSA key to be rejected")
	}
}

func TestVerifyJWTAudienceForms(t *testing.T) {
	k := newTestKeys(t)
	tests := []struct {
		name    string
		aud     any
		wantErr bool
	}{
		{"string", "a", false},
		{"array containing resource", []string{"other", "a"}, false},
		{"single element array", []string{"a"}, false},
		{"array without resource", []string{"x", "y"}, true},
		{"empty array", []string{}, true},
		{"string mismatch", "x", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tok := k.signAlg(t, "EdDSA", "EdDSA", "ed", algClaims(tc.aud))
			_, err := verifyJWT(tok, "a", k.resolver(), time.Now(), time.Minute, false)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

func TestJWKSLoadsMixedKeyTypes(t *testing.T) {
	k := newTestKeys(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{
			k.jwk("ed", "EdDSA"), k.jwk("ec", "ES256"), k.jwk("rsa", "RS256"),
			{"kty": "oct", "kid": "sym", "k": "AAAA"},
			{"kty": "EC", "crv": "P-384", "kid": "p384", "x": "AAAA", "y": "AAAA"},
		}})
	}))
	defer srv.Close()
	c := newJWKSCache(srv.URL, srv.Client(), time.Minute)
	for kid, wantAlg := range map[string]string{"ed": "EdDSA", "ec": "ES256", "rsa": "RS256"} {
		key, err := c.PublicKey(kid)
		if err != nil {
			t.Fatalf("%s: %v", kid, err)
		}
		tok := k.signAlg(t, wantAlg, wantAlg, kid, algClaims("a"))
		if _, err := verifyJWT(tok, "a", func(string, string) (crypto.PublicKey, error) { return key, nil }, time.Now(), time.Minute, false); err != nil {
			t.Fatalf("%s verify: %v", kid, err)
		}
	}
	for _, kid := range []string{"sym", "p384"} {
		if _, err := c.PublicKey(kid); err == nil {
			t.Fatalf("%s should not be loaded", kid)
		}
	}
}

func TestJWKSKeyAlgPinning(t *testing.T) {
	k := newTestKeys(t)
	jwk := k.jwk("ec", "ES256")
	jwk["alg"] = "ES256"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{jwk}})
	}))
	defer srv.Close()
	v := New("a", WithJWKS(srv.URL))
	key, err := v.jwks.PublicKey("ec")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := key.(*ecdsa.PublicKey); !ok {
		t.Fatalf("key type %T", key)
	}
	if _, err := v.jwks.Key("ec", "ES256"); err != nil {
		t.Fatalf("matching alg: %v", err)
	}
	if _, err := v.jwks.Key("ec", "RS256"); err == nil {
		t.Fatal("JWK alg pin must reject a different header alg")
	}
}

func TestMiddlewareAcceptsES256AndRS256ViaJWKS(t *testing.T) {
	k := newTestKeys(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{
			k.jwk("ed", "EdDSA"), k.jwk("ec", "ES256"), k.jwk("rsa", "RS256")}})
	}))
	defer srv.Close()
	v := New(testResource, WithJWKS(srv.URL))
	tests := []struct{ alg, kid string }{{"EdDSA", "ed"}, {"ES256", "ec"}, {"RS256", "rsa"}}
	for _, tc := range tests {
		t.Run(tc.alg, func(t *testing.T) {
			tok := k.signAlg(t, tc.alg, tc.alg, tc.kid, map[string]any{
				"iss": "i", "sub": "u", "aud": []string{"other", testResource},
				"exp": time.Now().Add(time.Hour).Unix(), "jti": "j", "scope": "read",
			})
			rec := runMiddleware(v, "Bearer "+tok)
			if rec.Code != http.StatusOK {
				t.Fatalf("status %d body=%s", rec.Code, rec.Body.String())
			}
		})
	}
	// Key-type confusion through the full stack: ES256 header naming the EdDSA kid.
	tok := k.signAlg(t, "ES256", "ES256", "ed", algClaims(testResource))
	if rec := runMiddleware(v, "Bearer "+tok); rec.Code != http.StatusUnauthorized {
		t.Fatalf("confusion status %d", rec.Code)
	}
}

func TestJWKSRejectsWeakRSAAndOffCurveEC(t *testing.T) {
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	weak := map[string]any{"kty": "RSA", "kid": "weak",
		"n": base64.RawURLEncoding.EncodeToString(small.N.Bytes()), "e": "AQAB"}
	k := newTestKeys(t)
	offCurve := k.jwk("bad", "ES256")
	offCurve["y"] = base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	good := k.jwk("good", "EdDSA")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{weak, offCurve, good}})
	}))
	defer srv.Close()
	c := newJWKSCache(srv.URL, srv.Client(), time.Minute)
	if _, err := c.PublicKey("good"); err != nil {
		t.Fatalf("good: %v", err)
	}
	for _, kid := range []string{"weak", "bad"} {
		if _, err := c.PublicKey(kid); err == nil {
			t.Fatalf("%s must not load", kid)
		}
	}
}
