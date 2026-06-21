package theauth

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/glincker/theauth-go/internal/ulid"
)

func TestUserZeroValueValid(t *testing.T) {
	u := User{}
	if u.Email != "" {
		t.Fatalf("zero User should have empty Email, got %q", u.Email)
	}
	if u.EmailVerifiedAt != nil {
		t.Fatal("zero User should have nil EmailVerifiedAt")
	}
	if !u.CreatedAt.IsZero() {
		t.Fatal("zero User should have zero CreatedAt")
	}
}

// TestUserJSONShape verifies the JSON shape returned to API clients:
// lowerCamelCase keys, ULID as a string (not byte array), TokenHash never
// leaked when serializing a Session.
func TestUserJSONShape(t *testing.T) {
	u := User{ID: ulid.New(), Email: "shape@h.com", Name: "Shape"}
	b, err := json.Marshal(u)
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	if !strings.Contains(got, `"email":"shape@h.com"`) {
		t.Fatalf("expected lowerCamel email key; got %s", got)
	}
	if !strings.Contains(got, `"avatarUrl":`) {
		t.Fatalf("expected avatarUrl key; got %s", got)
	}
	// ULID should serialize as a Crockford-base32 string via MarshalText,
	// NOT as a base64-encoded byte array.
	idStr := u.ID.String()
	if !strings.Contains(got, `"id":"`+idStr+`"`) {
		t.Fatalf("expected ULID string %q in JSON; got %s", idStr, got)
	}
}

func TestSessionJSONOmitsTokenHash(t *testing.T) {
	s := Session{
		ID:        ulid.New(),
		UserID:    ulid.New(),
		TokenHash: []byte("super-secret-hash"),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	if strings.Contains(got, "tokenHash") || strings.Contains(got, "TokenHash") || strings.Contains(got, "super-secret-hash") {
		t.Fatalf("session JSON must never include TokenHash; got %s", got)
	}
	if !strings.Contains(got, `"userId":"`) {
		t.Fatalf("expected userId key; got %s", got)
	}
}

// TestWebAuthnCredentialJSONOmitsPublicKey ensures the COSE public key bytes
// never leak through a JSON response (PublicKey is opaque material that an
// attacker could use offline; only metadata should reach the wire).
func TestWebAuthnCredentialJSONOmitsPublicKey(t *testing.T) {
	c := WebAuthnCredential{
		ID:           ulid.New(),
		UserID:       ulid.New(),
		CredentialID: []byte{1, 2, 3, 4},
		PublicKey:    []byte("secret-cose-bytes"),
		Name:         "MacBook",
	}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	if strings.Contains(got, "publicKey") || strings.Contains(got, "PublicKey") || strings.Contains(got, "secret-cose-bytes") {
		t.Fatalf("WebAuthnCredential JSON must omit PublicKey; got %s", got)
	}
	if !strings.Contains(got, `"name":"MacBook"`) {
		t.Fatalf("expected name key; got %s", got)
	}
}

// TestTOTPSecretJSONOmitsSecret ensures the encrypted secret never serializes
// over JSON, even though it is already ciphertext (defense in depth: the wire
// shape must not give anyone a starting point).
func TestTOTPSecretJSONOmitsSecret(t *testing.T) {
	s := TOTPSecret{UserID: ulid.New(), SecretEnc: []byte("ciphertext-bytes")}
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	if strings.Contains(got, "secretEnc") || strings.Contains(got, "SecretEnc") || strings.Contains(got, "ciphertext-bytes") {
		t.Fatalf("TOTPSecret JSON must omit SecretEnc; got %s", got)
	}
}

// TestRecoveryCodeJSONOmitsHash ensures the per-code hash never serializes.
func TestRecoveryCodeJSONOmitsHash(t *testing.T) {
	c := RecoveryCode{ID: ulid.New(), UserID: ulid.New(), CodeHash: []byte("hash-bytes")}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	if strings.Contains(got, "codeHash") || strings.Contains(got, "CodeHash") || strings.Contains(got, "hash-bytes") {
		t.Fatalf("RecoveryCode JSON must omit CodeHash; got %s", got)
	}
}

// TestAuthLevelConstants pins the wire string values so a future rename
// doesn't silently break existing rows in the sessions table.
func TestAuthLevelConstants(t *testing.T) {
	if AuthLevelFull != "full" {
		t.Fatalf("AuthLevelFull drift: got %q want %q", AuthLevelFull, "full")
	}
	if AuthLevelPending2FA != "pending_2fa" {
		t.Fatalf("AuthLevelPending2FA drift: got %q want %q", AuthLevelPending2FA, "pending_2fa")
	}
}

func TestSessionExpired(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name     string
		expires  time.Time
		revoked  *time.Time
		expected bool
	}{
		{"not expired, not revoked", now.Add(time.Hour), nil, false},
		{"expired, not revoked", now.Add(-time.Hour), nil, true},
		{"not expired, revoked", now.Add(time.Hour), &now, true},
		{"exactly at expiry boundary", now, nil, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := Session{ExpiresAt: c.expires, RevokedAt: c.revoked}
			if got := s.Expired(now); got != c.expected {
				t.Errorf("got %v, want %v", got, c.expected)
			}
		})
	}
}
