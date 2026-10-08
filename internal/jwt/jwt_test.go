package jwt_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2/internal/jwt"
)

func TestSignAndVerifyRoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	claims := jwt.Claims{
		Iss:      "https://auth.example.com",
		Sub:      "user-123",
		Aud:      "https://files.example.com/mcp",
		Exp:      time.Now().Add(time.Hour).Unix(),
		Iat:      time.Now().Unix(),
		Jti:      "jti-1",
		ClientID: "client-abc",
		Scope:    "files.read",
	}
	tok, err := jwt.Sign(claims, "kid-1", priv)
	if err != nil {
		t.Fatal(err)
	}
	got, err := jwt.Verify(tok, func(kid string) (ed25519.PublicKey, bool) {
		if kid != "kid-1" {
			return nil, false
		}
		return pub, true
	}, "https://files.example.com/mcp", time.Now())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.Sub != "user-123" || got.Aud != "https://files.example.com/mcp" {
		t.Fatalf("verify returned wrong claims: %+v", got)
	}
}

func TestVerifyRejectsAlgConfusion(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	// Craft an alg=none token: header.payload.<empty signature>.
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"at+jwt","kid":"kid-1"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"x","exp":99999999999}`))
	tok := header + "." + payload + "."
	_, err := jwt.Verify(tok, func(string) (ed25519.PublicKey, bool) { return pub, true }, "", time.Now())
	if err == nil {
		t.Fatal("expected alg=none rejection")
	}
}

func TestVerifyRejectsTamperedSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	tok, _ := jwt.Sign(jwt.Claims{
		Iss: "x", Sub: "y", Aud: "z",
		Exp: time.Now().Add(time.Hour).Unix(),
		Iat: time.Now().Unix(), Jti: "j",
	}, "kid-1", priv)
	parts := strings.Split(tok, ".")
	// Flip a bit in the signature segment.
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	sig[0] ^= 0xff
	parts[2] = base64.RawURLEncoding.EncodeToString(sig)
	tampered := strings.Join(parts, ".")
	if _, err := jwt.Verify(tampered, func(string) (ed25519.PublicKey, bool) { return pub, true }, "", time.Now()); err == nil {
		t.Fatal("expected tampered signature rejection")
	}
}

func TestVerifyRejectsExpired(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	tok, _ := jwt.Sign(jwt.Claims{
		Iss: "x", Sub: "y", Aud: "z",
		Exp: time.Now().Add(-time.Hour).Unix(),
		Iat: time.Now().Add(-2 * time.Hour).Unix(), Jti: "j",
	}, "kid-1", priv)
	if _, err := jwt.Verify(tok, func(string) (ed25519.PublicKey, bool) { return pub, true }, "", time.Now()); err == nil {
		t.Fatal("expected expired-token rejection")
	}
}

func TestVerifyRejectsAudMismatch(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	tok, _ := jwt.Sign(jwt.Claims{
		Iss: "x", Sub: "y", Aud: "z",
		Exp: time.Now().Add(time.Hour).Unix(),
		Iat: time.Now().Unix(), Jti: "j",
	}, "kid-1", priv)
	if _, err := jwt.Verify(tok, func(string) (ed25519.PublicKey, bool) { return pub, true }, "other", time.Now()); err == nil {
		t.Fatal("expected aud mismatch rejection")
	}
}

func TestVerifyTypRequirement(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	resolve := func(string) (ed25519.PublicKey, bool) { return pub, true }
	mk := func(typ string) string {
		h := map[string]string{"alg": "EdDSA", "kid": "k"}
		if typ != "" {
			h["typ"] = typ
		}
		hb, _ := json.Marshal(h)
		cb, _ := json.Marshal(map[string]any{"iss": "i", "exp": time.Now().Add(time.Hour).Unix()})
		in := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(cb)
		return in + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, []byte(in)))
	}
	tests := []struct {
		name    string
		typ     string
		opts    jwt.VerifyOptions
		wantErr bool
	}{
		{"at+jwt ok", "at+jwt", jwt.VerifyOptions{}, false},
		{"missing rejected", "", jwt.VerifyOptions{}, true},
		{"missing tolerated", "", jwt.VerifyOptions{AllowMissingTyp: true}, false},
		{"wrong typ rejected even tolerant", "JWT", jwt.VerifyOptions{AllowMissingTyp: true}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := jwt.VerifyOpts(mk(tc.typ), resolve, "", time.Now(), tc.opts)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tc.wantErr)
			}
		})
	}
}
