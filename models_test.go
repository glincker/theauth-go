package theauth

import (
	"testing"
	"time"
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
