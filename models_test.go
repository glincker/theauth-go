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
