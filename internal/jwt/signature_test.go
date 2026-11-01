package jwt_test

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/glincker/theauth-go/v2/internal/jwt"
)

func edKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestVerifySignature(t *testing.T) {
	pub, priv := edKey(t)
	otherPub, _ := edKey(t)
	tok, err := jwt.SignPayload(map[string]any{"aud": []string{"a", "b"}, "events": "x"}, jwt.TypeLogoutToken, "k1", priv)
	if err != nil {
		t.Fatal(err)
	}
	resolveFor := func(kid string, key crypto.PublicKey) jwt.KeyResolver {
		return func(got string) (string, crypto.PublicKey, bool) {
			if got != kid {
				return "", nil, false
			}
			return jwt.AlgEdDSA, key, true
		}
	}
	parts := strings.Split(tok, ".")
	tests := []struct {
		name    string
		token   string
		resolve jwt.KeyResolver
		typ     string
		wantErr string
	}{
		{"valid", tok, resolveFor("k1", pub), jwt.TypeLogoutToken, ""},
		{"wrong key", tok, resolveFor("k1", otherPub), jwt.TypeLogoutToken, "signature mismatch"},
		{"unknown kid", tok, resolveFor("zzz", pub), jwt.TypeLogoutToken, "unknown kid"},
		{"typ confusion", tok, resolveFor("k1", pub), jwt.TypeAccessToken, "unsupported typ"},
		{"two segments", parts[0] + "." + parts[1], resolveFor("k1", pub), jwt.TypeLogoutToken, "three segments"},
		{"tampered payload", parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"aud":"evil"}`)) + "." + parts[2], resolveFor("k1", pub), jwt.TypeLogoutToken, "signature mismatch"},
		{"bad header b64", "!!." + parts[1] + "." + parts[2], resolveFor("k1", pub), jwt.TypeLogoutToken, "header decode"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h, payload, err := jwt.VerifySignature(tc.token, tc.resolve, tc.typ)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if h.Kid != "k1" || !strings.Contains(string(payload), `"events":"x"`) {
				t.Fatalf("header %+v payload %s", h, payload)
			}
		})
	}
}

func TestSignPayloadRejectsShortKey(t *testing.T) {
	if _, err := jwt.SignPayload(map[string]any{"a": 1}, "t", "k", ed25519.PrivateKey{1, 2}); err == nil {
		t.Fatal("want error for malformed private key")
	}
}

func TestPeekHeader(t *testing.T) {
	_, priv := edKey(t)
	tok, err := jwt.Sign(jwt.Claims{Sub: "u"}, "kid-9", priv)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		token   string
		wantKid string
		wantErr bool
	}{
		{"valid", tok, "kid-9", false},
		{"too few segments", "a.b", "", true},
		{"bad base64", "!!.b.c", "", true},
		{"bad json", base64.RawURLEncoding.EncodeToString([]byte("nope")) + ".b.c", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h, err := jwt.PeekHeader(tc.token)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if h.Kid != tc.wantKid || (!tc.wantErr && h.Alg != jwt.AlgEdDSA) {
				t.Fatalf("header = %+v", h)
			}
		})
	}
}

func TestClaimsMarshalJSONExtra(t *testing.T) {
	c := jwt.Claims{Sub: "real", Extra: map[string]any{"sub": "forged", "act": map[string]any{"sub": "agent"}}}
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if m["sub"] != "real" {
		t.Fatalf("registered claim must win over Extra, got %v", m["sub"])
	}
	if _, ok := m["act"].(map[string]any); !ok {
		t.Fatalf("extra claim missing: %s", raw)
	}
}
