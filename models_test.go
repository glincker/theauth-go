package theauth

import (
	"testing"
	"time"
)

func TestUserZeroValueValid(t *testing.T) {
	u := User{}
	if u.ID.String() == "" && u.Email != "" {
		t.Fatal("zero User should have empty email")
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
