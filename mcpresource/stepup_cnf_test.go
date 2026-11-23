package mcpresource

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// RFC 9449 section 7 (Figures 13 and 14): a DPoP protected resource request.
const (
	rfc9449Token = "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU"
	rfc9449JKT   = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
	rfc9449Proof = "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JEQSIsImNydiI6IlAtMjU2In19." +
		"eyJqdGkiOiJlMWozVl9iS2ljOC1MQUVCIiwiaHRtIjoiR0VUIiwiaHR1IjoiaHR0cHM6Ly9yZXNvdXJjZS5leGFtcGxlLm9yZy9wcm90ZWN0ZWRyZXNvdXJjZSIsImlhdCI6MTU2MjI2MjYxOCwiYXRoIjoiZlVIeU8ycjJaM0RaNTNFc05yV0JiMHhXWG9hTnk1OUlpS0NBcWtzbVFFbyJ9." +
		"2oW9RP35yRqzhrtNP86L-Ey71EOptxRimPPToA1plemAgR6pxHF8y6-yqyVnmcw6Fy1dqd-jfxSYoMxhAJpLjA"
	rfc9449URL = "https://resource.example.org/protectedresource"
	rfc9449IAT = 1562262618
)

func TestRFC9449ResourceRequestVector(t *testing.T) {
	now := time.Unix(rfc9449IAT, 0)
	params := dpopVerifyParams{method: "GET", url: rfc9449URL, accessToken: rfc9449Token, requiredJKT: rfc9449JKT, now: now}

	v := newDPoPVerifier(nil, 0, 0, 0)
	thumb, err := v.verifyAndBind(rfc9449Proof, params)
	if err != nil {
		t.Fatalf("RFC 9449 Figure 13 proof refused: %v", err)
	}
	if thumb != rfc9449JKT {
		t.Fatalf("thumbprint %q want %q", thumb, rfc9449JKT)
	}
	if got := dpopAccessTokenHash(rfc9449Token); got != "fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo" {
		t.Fatalf("ath %q", got)
	}
	// Same proof again is a replay.
	if _, err := v.verifyAndBind(rfc9449Proof, params); err != errDPoPReplay {
		t.Fatalf("replay: %v", err)
	}
	// Wrong token, wrong method, wrong URL, wrong key, stale clock.
	cases := map[string]func(p *dpopVerifyParams){
		"token":  func(p *dpopVerifyParams) { p.accessToken = "other" },
		"method": func(p *dpopVerifyParams) { p.method = "POST" },
		"url":    func(p *dpopVerifyParams) { p.url = "https://resource.example.org/other" },
		"jkt":    func(p *dpopVerifyParams) { p.requiredJKT = "AAAA" },
		"clock":  func(p *dpopVerifyParams) { p.now = now.Add(time.Hour) },
	}
	for name, mutate := range cases {
		p := params
		mutate(&p)
		if _, err := newDPoPVerifier(nil, 0, 0, 0).verifyAndBind(rfc9449Proof, p); err == nil {
			t.Fatalf("%s mutation accepted", name)
		}
	}
}

// RFC 7638 section 3.1 example RSA key and thumbprint.
func TestRFC7638ThumbprintVector(t *testing.T) {
	n := "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
	got, err := dpopThumbprint(&dpopJWK{Kty: "RSA", N: n, E: "AQAB"})
	if err != nil {
		t.Fatal(err)
	}
	if got != "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs" {
		t.Fatalf("thumbprint %q", got)
	}
}

// proofWithNonce signs an ES256 proof that carries nonce.
func proofWithNonce(t *testing.T, priv *ecdsa.PrivateKey, method, url, token, nonce string, iat time.Time) string {
	t.Helper()
	jwk := map[string]string{"kty": "EC", "crv": "P-256",
		"x": base64.RawURLEncoding.EncodeToString(priv.X.FillBytes(make([]byte, 32))),
		"y": base64.RawURLEncoding.EncodeToString(priv.Y.FillBytes(make([]byte, 32)))}
	ath := sha256.Sum256([]byte(token))
	jtiRaw := make([]byte, 12)
	_, _ = rand.Read(jtiRaw)
	claims := map[string]any{"jti": base64.RawURLEncoding.EncodeToString(jtiRaw),
		"htm": method, "htu": url, "iat": iat.Unix(), "ath": base64.RawURLEncoding.EncodeToString(ath[:])}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	hj, _ := json.Marshal(map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": jwk})
	pj, _ := json.Marshal(claims)
	in := base64.RawURLEncoding.EncodeToString(hj) + "." + base64.RawURLEncoding.EncodeToString(pj)
	d := sha256.Sum256([]byte(in))
	r, s, err := ecdsa.Sign(rand.Reader, priv, d[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	return in + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func jktOf(priv *ecdsa.PrivateKey) string {
	j := &dpopJWK{Kty: "EC", Crv: "P-256",
		X: base64.RawURLEncoding.EncodeToString(priv.X.FillBytes(make([]byte, 32))),
		Y: base64.RawURLEncoding.EncodeToString(priv.Y.FillBytes(make([]byte, 32)))}
	s, _ := dpopThumbprint(j)
	return s
}

func TestDPoPServerNonce(t *testing.T) {
	f := newDPoPFakeAS(t)
	defer f.jwksServer.Close()
	defer f.introspectServer.Close()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	const url = "https://files.example.com/mcp/x"
	v := New("https://files.example.com/mcp", WithJWKS(f.jwksServer.URL),
		WithDPoPVerification(nil, 0, 0), WithDPoPNonce([]byte("shared-secret"), time.Minute))
	token := mintDPoPBoundToken(t, f, jktOf(priv), time.Now().Add(time.Hour))
	do := func(proof string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", url, nil)
		r.Header.Set("Authorization", "DPoP "+token)
		r.Header.Set("DPoP", proof)
		rr := httptest.NewRecorder()
		v.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(rr, r)
		return rr
	}

	// No nonce: RFC 9449 section 9 challenge with a fresh DPoP-Nonce.
	rr := do(proofWithNonce(t, priv, "GET", url, token, "", time.Now()))
	if rr.Code != 401 {
		t.Fatalf("no nonce: %d", rr.Code)
	}
	www := rr.Header().Get("WWW-Authenticate")
	for _, want := range []string{`DPoP error="use_dpop_nonce"`, `algs="ES256 ES384 RS256 PS256 EdDSA"`} {
		if !strings.Contains(www, want) {
			t.Fatalf("WWW-Authenticate %q missing %q", www, want)
		}
	}
	nonce := rr.Header().Get("DPoP-Nonce")
	if nonce == "" {
		t.Fatal("no DPoP-Nonce header")
	}
	// Forged nonce is refused the same way.
	if rr := do(proofWithNonce(t, priv, "GET", url, token, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", time.Now())); rr.Code != 401 || rr.Header().Get("DPoP-Nonce") == "" {
		t.Fatalf("forged nonce: %d", rr.Code)
	}
	// Retry with the issued nonce succeeds and hands out the next one.
	rr = do(proofWithNonce(t, priv, "GET", url, token, nonce, time.Now()))
	if rr.Code != 200 {
		t.Fatalf("with nonce: %d %s", rr.Code, rr.Header().Get("WWW-Authenticate"))
	}
	if rr.Header().Get("DPoP-Nonce") == "" {
		t.Fatal("success response carries no next nonce")
	}
	// A second instance with the same secret accepts the nonce.
	other := New("https://files.example.com/mcp", WithJWKS(f.jwksServer.URL),
		WithDPoPVerification(nil, 0, 0), WithDPoPNonce([]byte("shared-secret"), time.Minute))
	if !other.dpop.nonces.valid(nonce, time.Now()) {
		t.Fatal("shared secret nonce rejected by sibling")
	}
	stranger := New("https://files.example.com/mcp", WithJWKS(f.jwksServer.URL),
		WithDPoPVerification(nil, 0, 0), WithDPoPNonce([]byte("different"), time.Minute))
	if stranger.dpop.nonces.valid(nonce, time.Now()) {
		t.Fatal("nonce from another secret accepted")
	}
}

func TestDPoPNonceWindow(t *testing.T) {
	n := newDPoPNonces([]byte("k"), time.Minute)
	now := time.Unix(1_800_000_000, 0)
	nonce := n.issue(now)
	if !n.valid(nonce, now) || !n.valid(nonce, now.Add(time.Minute)) {
		t.Fatal("nonce should live through the next window")
	}
	if n.valid(nonce, now.Add(3*time.Minute)) {
		t.Fatal("expired nonce accepted")
	}
	if n.valid("", now) || n.valid("!!", now) {
		t.Fatal("garbage nonce accepted")
	}
}

type countingReplay struct {
	mu   sync.Mutex
	seen map[string]bool
	n    atomic.Int32
}

func (c *countingReplay) Remember(jti string, _ time.Time) bool {
	c.n.Add(1)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.seen[jti] {
		return false
	}
	c.seen[jti] = true
	return true
}

func TestDPoPReplayCacheIsPluggable(t *testing.T) {
	cache := &countingReplay{seen: map[string]bool{}}
	v := newDPoPVerifier(nil, 0, 0, 0)
	v.replay = cache
	p := dpopVerifyParams{method: "GET", url: rfc9449URL, accessToken: rfc9449Token, requiredJKT: rfc9449JKT, now: time.Unix(rfc9449IAT, 0)}
	if _, err := v.verifyAndBind(rfc9449Proof, p); err != nil {
		t.Fatal(err)
	}
	if _, err := v.verifyAndBind(rfc9449Proof, p); err != errDPoPReplay {
		t.Fatalf("replay not caught by custom cache: %v", err)
	}
	if cache.n.Load() != 2 {
		t.Fatalf("custom cache consulted %d times", cache.n.Load())
	}
}

func TestDPoPErrorCodes(t *testing.T) {
	f := newDPoPFakeAS(t)
	defer f.jwksServer.Close()
	defer f.introspectServer.Close()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	v := New("https://files.example.com/mcp", WithJWKS(f.jwksServer.URL), WithDPoPVerification(nil, 0, 0))
	token := mintDPoPBoundToken(t, f, jktOf(priv), time.Now().Add(time.Hour))
	call := func(proof string) string {
		r := httptest.NewRequest("GET", "https://files.example.com/mcp/x", nil)
		r.Header.Set("Authorization", "DPoP "+token)
		if proof != "" {
			r.Header.Set("DPoP", proof)
		}
		rr := httptest.NewRecorder()
		v.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(rr, r)
		return rr.Header().Get("WWW-Authenticate")
	}
	if got := call(""); !strings.HasPrefix(got, `DPoP error="invalid_token"`) {
		t.Fatalf("missing proof: %q", got)
	}
	if got := call("garbage"); !strings.HasPrefix(got, `DPoP error="invalid_dpop_proof"`) {
		t.Fatalf("garbage proof: %q", got)
	}
}

// mTLS (RFC 8705).

func testCert(t *testing.T) *x509.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCertThumbprint(t *testing.T) {
	c := testCert(t)
	sum := sha256.Sum256(c.Raw)
	if got := CertThumbprint(c); got != base64.RawURLEncoding.EncodeToString(sum[:]) || strings.ContainsAny(got, "=+/") {
		t.Fatalf("thumbprint %q", got)
	}
}

func TestMTLSBoundToken(t *testing.T) {
	cert := testCert(t)
	other := testCert(t)
	thumb := CertThumbprint(cert)
	run := func(t *testing.T, claims map[string]any, req func(*http.Request), opts ...Option) (*httptest.ResponseRecorder, *Principal) {
		f := newFakeAS(t)
		v := newValidatorAgainst(f, opts...)
		base := map[string]any{"iss": testResource, "sub": "u", "aud": testResource, "exp": time.Now().Add(time.Hour).Unix(),
			"iat": time.Now().Unix(), "jti": "j", "client_id": "c", "scope": "read"}
		for k, val := range claims {
			base[k] = val
		}
		tok := signToken(t, f.kid, f.priv, base)
		var got *Principal
		h := v.Middleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { got, _ = PrincipalFromContext(r.Context()) }))
		r := httptest.NewRequest("GET", "https://mcp.example.com/tools", nil)
		r.Header.Set("Authorization", "Bearer "+tok)
		if req != nil {
			req(r)
		}
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, r)
		return rr, got
	}
	cnf := map[string]any{"cnf": map[string]any{"x5t#S256": thumb}}
	withCert := func(c *x509.Certificate) func(*http.Request) {
		return func(r *http.Request) {
			r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{c}}
		}
	}
	t.Run("matching cert", func(t *testing.T) {
		rr, p := run(t, cnf, withCert(cert))
		if rr.Code != 200 || p == nil || p.CnfX5tS256 != thumb {
			t.Fatalf("status %d principal %+v", rr.Code, p)
		}
	})
	t.Run("other cert refused", func(t *testing.T) {
		if rr, _ := run(t, cnf, withCert(other)); rr.Code != 401 {
			t.Fatalf("status %d", rr.Code)
		}
	})
	t.Run("no cert refused", func(t *testing.T) {
		if rr, _ := run(t, cnf, nil); rr.Code != 401 {
			t.Fatalf("status %d", rr.Code)
		}
	})
	t.Run("proxy thumbprint", func(t *testing.T) {
		hook := WithClientCertThumbprint(func(r *http.Request) string { return r.Header.Get("X-Client-Cert-Sha256") })
		rr, p := run(t, cnf, func(r *http.Request) { r.Header.Set("X-Client-Cert-Sha256", thumb) }, hook)
		if rr.Code != 200 || p.CnfX5tS256 != thumb {
			t.Fatalf("status %d", rr.Code)
		}
		if rr, _ := run(t, cnf, func(r *http.Request) { r.Header.Set("X-Client-Cert-Sha256", "wrong") }, hook); rr.Code != 401 {
			t.Fatalf("wrong proxy thumbprint: %d", rr.Code)
		}
	})
	t.Run("jkt and x5t both required", func(t *testing.T) {
		both := map[string]any{"cnf": map[string]any{"x5t#S256": thumb, "jkt": "some-jkt"}}
		// The certificate matches but there is no DPoP proof and no verifier.
		if rr, _ := run(t, both, withCert(cert)); rr.Code != 401 {
			t.Fatalf("status %d", rr.Code)
		}
	})
	t.Run("unbound token unaffected", func(t *testing.T) {
		if rr, _ := run(t, nil, nil); rr.Code != 200 {
			t.Fatalf("status %d", rr.Code)
		}
	})
}

func TestOpaqueMTLS(t *testing.T) {
	cert := testCert(t)
	const tok = "mtls-bound-opaque-token"
	a := newOpaqueAS(t)
	a.set(tok, activeAnswer(map[string]any{"cnf": map[string]any{"x5t#S256": CertThumbprint(cert)}}))
	v := newOpaqueValidator(a, WithClientCertThumbprint(func(r *http.Request) string { return r.Header.Get("X-Cert") }))
	if rec := serve(v, "Bearer", tok, map[string]string{"X-Cert": CertThumbprint(cert)}); rec.Code != 200 {
		t.Fatalf("matching: %d", rec.Code)
	}
	if rec := serve(v, "Bearer", tok, nil); rec.Code != 401 {
		t.Fatalf("missing cert: %d", rec.Code)
	}
}

// Step-up (RFC 9470).

func TestACRLadder(t *testing.T) {
	tests := []struct {
		have   string
		wanted []string
		ok     bool
	}{
		{ACRPhishingResistant, []string{ACRMFA}, true},
		{ACRMFA, []string{ACRMFA}, true},
		{ACRSingleFactor, []string{ACRMFA}, false},
		{ACRMFA, []string{ACRPhishingResistant}, false},
		{ACRMFA, []string{ACRPhishingResistant, ACRMFA}, true},
		{"", []string{ACRNone}, false},
		{"custom", []string{"custom"}, true},
		{"custom", []string{ACRNone}, false},
		{ACRPhishingResistant, []string{"custom"}, false},
		{ACRPhishingResistant, []string{"custom", ACRMFA}, true},
	}
	for _, tc := range tests {
		if got := acrSatisfied(tc.have, tc.wanted); got != tc.ok {
			t.Errorf("acrSatisfied(%q, %v) = %v", tc.have, tc.wanted, got)
		}
	}
}

func TestStepUpAuthTimeInFuture(t *testing.T) {
	now := time.Now()
	p := &Principal{AuthTime: now.Add(time.Hour)}
	if (StepUp{MaxAge: time.Minute}).Satisfied(p, now) {
		t.Fatal("auth_time an hour ahead was accepted")
	}
	p.AuthTime = now.Add(10 * time.Second)
	if !(StepUp{MaxAge: time.Minute}).Satisfied(p, now) {
		t.Fatal("small skew refused")
	}
}

func TestStepUpOrderedACROverHTTP(t *testing.T) {
	rec := guarded(t, map[string]any{"acr": ACRPhishingResistant, "auth_time": time.Now().Unix()},
		func(v *Validator) func(http.Handler) http.Handler {
			return v.RequireStepUp(StepUp{ACRValues: []string{ACRMFA}, MaxAge: 5 * time.Minute})
		})
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	rec = guarded(t, map[string]any{"acr": ACRSingleFactor, "auth_time": time.Now().Unix()},
		func(v *Validator) func(http.Handler) http.Handler {
			return v.RequireStepUp(StepUp{ACRValues: []string{ACRMFA}, MaxAge: 5 * time.Minute})
		})
	www := rec.Header().Get("WWW-Authenticate")
	if rec.Code != 401 || !strings.Contains(www, `acr_values="`+ACRMFA+`"`) || !strings.Contains(www, `max_age="300"`) {
		t.Fatalf("status %d www %q", rec.Code, www)
	}
}

// A proof near the edge of the acceptance window (proofMaxAge plus skew) must
// still be remembered, or it could be replayed once its entry expired.
func TestDPoPReplayNearWindowEdge(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	const url = "https://files.example.com/mcp/x"
	const token = "tok"
	now := time.Now()
	v := newDPoPVerifier(nil, time.Minute, time.Minute, 0)
	proof := proofWithNonce(t, priv, "GET", url, token, "", now.Add(-100*time.Second))
	p := dpopVerifyParams{method: "GET", url: url, accessToken: token, now: now}
	if _, err := v.verifyAndBind(proof, p); err != nil {
		t.Fatalf("first use: %v", err)
	}
	if _, err := v.verifyAndBind(proof, p); err != errDPoPReplay {
		t.Fatalf("replay near the window edge: %v", err)
	}
}
