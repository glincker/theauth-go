package webauthn_test

import (
	"context"
	"crypto/rand"
	"testing"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/internal/ulid"
	"github.com/glincker/theauth-go/v2/storage/memory"
)

// TestPasskeyLoginFiresOnSignin proves OnSignin fires once per successful
// passkey login and never for registration or a rejected assertion.
func TestPasskeyLoginFiresOnSignin(t *testing.T) {
	tests := []struct {
		name        string
		logins      int
		freezeAfter bool
		wantSignin  int
	}{
		{"registration alone does not fire", 0, false, 0},
		{"one login fires once", 1, false, 1},
		{"two logins fire twice", 2, false, 2},
		{"rejected replay does not fire", 2, true, 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			key := make([]byte, 32)
			_, _ = rand.Read(key)
			var seen []theauth.Session
			store := memory.New()
			a, err := theauth.New(theauth.Config{
				Storage: store, BaseURL: "http://localhost", EncryptionKey: key,
				WebAuthn: &theauth.WebAuthnConfig{RPID: testRPID, RPDisplayName: "Example", RPOrigins: []string{testOrigin}},
				LifecycleHooks: &theauth.LifecycleHooks{
					OnSignin: func(_ context.Context, u *theauth.User, s *theauth.Session) error {
						if u.ID != s.UserID {
							t.Errorf("hook user %v does not match session user %v", u.ID, s.UserID)
						}
						seen = append(seen, *s)
						return nil
					},
				},
				RateLimitPerIP: 1000, RateLimitPerEmail: 1000,
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(a.Close)
			u, _ := store.CreateUser(ctx, theauth.User{ID: ulid.New(), Email: "pk-hook@example.com"})
			va := newVirtualAuthenticator(t)
			if _, err := register(t, a, u.ID, va); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < tc.logins; i++ {
				if tc.freezeAfter && i == 1 {
					va.freezeCount = true
				}
				err := login(t, a, u.ID, va)
				if tc.freezeAfter && i == 1 {
					if err == nil {
						t.Fatal("replayed counter must be rejected")
					}
					continue
				}
				if err != nil {
					t.Fatalf("login %d: %v", i, err)
				}
			}
			if len(seen) != tc.wantSignin {
				t.Fatalf("OnSignin calls: want %d; got %d", tc.wantSignin, len(seen))
			}
		})
	}
}
