package mcpresource

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// A JWKS outage may serve cached keys only up to the max-stale bound.
func TestJWKSMaxStaleBound(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	var down atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if down.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{{
			"kty": "OKP", "crv": "Ed25519", "kid": "k1", "x": base64.RawURLEncoding.EncodeToString(pub),
		}}})
	}))
	defer srv.Close()

	tests := []struct {
		name    string
		elapsed time.Duration
		wantErr bool
	}{
		{"within bound serves stale key", 30 * time.Minute, false},
		{"past bound fails closed", 2 * time.Hour, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			down.Store(false)
			now := time.Unix(1_800_000_000, 0)
			c := newJWKSCache(srv.URL, srv.Client(), time.Minute)
			c.maxStale = time.Hour
			c.minRefreshInterval = 0
			c.now = func() time.Time { return now }
			if _, err := c.PublicKey("k1"); err != nil {
				t.Fatalf("prime: %v", err)
			}
			down.Store(true)
			now = now.Add(tc.elapsed)
			_, err := c.PublicKey("k1")
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

func TestVerifyJWTTypRequirement(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	resolve := func(string) (ed25519.PublicKey, error) { return pub, nil }
	claims := map[string]any{"iss": "i", "sub": "u", "aud": "a", "exp": time.Now().Add(time.Hour).Unix(), "jti": "j"}
	mk := func(typ string) string {
		h := map[string]string{"alg": "EdDSA", "kid": "k"}
		if typ != "" {
			h["typ"] = typ
		}
		hb, _ := json.Marshal(h)
		cb, _ := json.Marshal(claims)
		in := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(cb)
		return in + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, []byte(in)))
	}
	tests := []struct {
		name         string
		typ          string
		allowMissing bool
		wantErr      bool
	}{
		{"at+jwt accepted", "at+jwt", false, false},
		{"missing rejected by default", "", false, true},
		{"missing tolerated with flag", "", true, false},
		{"id token typ rejected", "JWT", true, true},
		{"id token typ rejected strict", "JWT", false, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := verifyJWT(mk(tc.typ), "a", resolve, time.Now(), time.Minute, tc.allowMissing)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tc.wantErr)
			}
		})
	}
}
