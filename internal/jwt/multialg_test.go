package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

type testKey struct {
	alg    string
	signer crypto.Signer
}

func newTestKeys(t *testing.T) map[string]testKey {
	t.Helper()
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rs, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]testKey{
		AlgEdDSA: {AlgEdDSA, ed}, AlgES256: {AlgES256, ec}, AlgRS256: {AlgRS256, rs},
	}
}

func resolverFor(keys map[string]testKey) KeyResolver {
	return func(kid string) (string, crypto.PublicKey, bool) {
		k, ok := keys[kid]
		if !ok {
			return "", nil, false
		}
		return k.alg, k.signer.Public(), true
	}
}

func claimsFor(now time.Time) Claims {
	return Claims{
		Iss: "https://as", Sub: "u", Aud: "https://rs", Exp: now.Add(time.Hour).Unix(), Iat: now.Unix(),
		Jti: "j", ClientID: "c", Scope: "a b",
	}
}

func TestSignWithVerifyWithRoundTrip(t *testing.T) {
	keys := newTestKeys(t)
	now := time.Now()
	for kid, k := range keys {
		t.Run(k.alg, func(t *testing.T) {
			tok, err := SignWith(claimsFor(now), TypeAccessToken, kid, k.alg, k.signer)
			if err != nil {
				t.Fatal(err)
			}
			got, err := VerifyWith(tok, resolverFor(keys), TypeAccessToken, "https://rs", now, VerifyOptions{})
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			if got.Sub != "u" || got.Scope != "a b" {
				t.Fatalf("claims: %+v", got)
			}
		})
	}
}

func TestVerifyWithRejections(t *testing.T) {
	keys := newTestKeys(t)
	now := time.Now()
	resolve := resolverFor(keys)
	good, err := SignWith(claimsFor(now), TypeAccessToken, AlgES256, AlgES256, keys[AlgES256].signer)
	if err != nil {
		t.Fatal(err)
	}
	// Rebuild a token with a chosen header, signing over the new input with the ES256 key.
	rebuild := func(mut func(h map[string]any)) string {
		parts := strings.Split(good, ".")
		raw, _ := base64.RawURLEncoding.DecodeString(parts[0])
		var h map[string]any
		_ = json.Unmarshal(raw, &h)
		mut(h)
		hb, _ := json.Marshal(h)
		return base64.RawURLEncoding.EncodeToString(hb) + "." + parts[1] + "." + parts[2]
	}

	tests := []struct {
		name  string
		token string
		aud   string
		now   time.Time
		opts  VerifyOptions
	}{
		{"alg none", rebuild(func(h map[string]any) { h["alg"] = "none" }), "", now, VerifyOptions{}},
		{"alg HS256", rebuild(func(h map[string]any) { h["alg"] = "HS256" }), "", now, VerifyOptions{}},
		{"alg confusion: header says RS256 for an EC key", rebuild(func(h map[string]any) { h["alg"] = AlgRS256 }), "", now, VerifyOptions{}},
		{"unknown kid", rebuild(func(h map[string]any) { h["kid"] = "nope" }), "", now, VerifyOptions{}},
		{"missing kid", rebuild(func(h map[string]any) { delete(h, "kid") }), "", now, VerifyOptions{}},
		{"wrong typ", rebuild(func(h map[string]any) { h["typ"] = "JWT" }), "", now, VerifyOptions{}},
		{"missing typ", rebuild(func(h map[string]any) { delete(h, "typ") }), "", now, VerifyOptions{}},
		{"tampered signature", good[:len(good)-4] + "AAAA", "", now, VerifyOptions{}},
		{"wrong audience", good, "https://other", now, VerifyOptions{}},
		{"expired", good, "", now.Add(2 * time.Hour), VerifyOptions{}},
		{"two segments", "a.b", "", now, VerifyOptions{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := VerifyWith(tc.token, resolve, TypeAccessToken, tc.aud, tc.now, tc.opts); err == nil {
				t.Fatal("token accepted")
			}
		})
	}

	t.Run("skew tolerates a just-expired token", func(t *testing.T) {
		at := time.Unix(claimsFor(now).Exp, 0).Add(10 * time.Second)
		if _, err := VerifyWith(good, resolve, TypeAccessToken, "", at, VerifyOptions{Skew: 30 * time.Second}); err != nil {
			t.Fatalf("within skew: %v", err)
		}
	})
	t.Run("missing typ allowed on request", func(t *testing.T) {
		fresh, _ := SignWith(claimsFor(now), "", AlgES256, AlgES256, keys[AlgES256].signer)
		if _, err := VerifyWith(fresh, resolve, TypeAccessToken, "", now, VerifyOptions{AllowMissingTyp: true}); err != nil {
			t.Fatalf("AllowMissingTyp: %v", err)
		}
	})
}

func TestSignWithRejectsMismatchedKey(t *testing.T) {
	keys := newTestKeys(t)
	now := time.Now()
	if _, err := SignWith(claimsFor(now), TypeAccessToken, "k", AlgRS256, keys[AlgES256].signer); err == nil {
		t.Fatal("RS256 with an EC key must fail")
	}
	if _, err := SignWith(claimsFor(now), TypeAccessToken, "k", AlgES256, keys[AlgEdDSA].signer); err == nil {
		t.Fatal("ES256 with an Ed25519 key must fail")
	}
	if _, err := SignWith(claimsFor(now), TypeAccessToken, "k", "HS256", keys[AlgEdDSA].signer); err == nil {
		t.Fatal("HS256 must be unsupported")
	}
	if _, err := SignWith(claimsFor(now), TypeAccessToken, "k", AlgEdDSA, nil); err == nil {
		t.Fatal("nil signer must fail")
	}
}

func TestSupportedAlg(t *testing.T) {
	for alg, want := range map[string]bool{AlgEdDSA: true, AlgES256: true, AlgRS256: true, "HS256": false, "none": false, "": false, "PS256": false} {
		if SupportedAlg(alg) != want {
			t.Errorf("SupportedAlg(%q) = %v", alg, !want)
		}
	}
}
