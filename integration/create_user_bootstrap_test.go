package integration

import (
	"context"
	"net/http"
	"testing"

	"github.com/glincker/theauth-go/v2"
)

// A user made by CreateUser counts as a user, so it closes the Bootstrap gate. These tests pin that
// behavior: the setup token cannot be used to set a first password on a seeded user.
func TestCreateUserBootstrapClosesGate(t *testing.T) {
	const email = "owner@example.com"
	signup := func(t *testing.T, a *theauth.TheAuth, addr, token string) *http.Response {
		t.Helper()
		h := mounted(a)
		rec := hpost(t, h, "/auth/email-password/signup", "1.1.1.1",
			map[string]string{"email": addr, "password": validPassword}, map[string]string{"X-Setup-Token": token})
		return rec.Result()
	}

	t.Run("seeded user then signup with the valid token is refused", func(t *testing.T) {
		a, store := hardenedAuth(t, func(c *theauth.Config) {
			c.Bootstrap = &theauth.BootstrapConfig{SetupToken: "s3cret-token", SuppressSetupTokenLog: true}
		})
		if _, err := a.CreateUser(context.Background(), theauth.CreateUserInput{Email: email}); err != nil {
			t.Fatal(err)
		}
		for _, addr := range []string{email, "OWNER@Example.com", "other@example.com"} {
			res := signup(t, a, addr, "s3cret-token")
			if res.StatusCode != http.StatusForbidden {
				t.Fatalf("signup %q: status %d, want 403", addr, res.StatusCode)
			}
		}
		rec := hpost(t, mounted(a), "/auth/email-password/signup", "1.1.1.1",
			map[string]string{"email": email, "password": validPassword}, map[string]string{"X-Setup-Token": "s3cret-token"})
		if c, _ := errBody(t, rec); c != theauth.CodeSignupClosed {
			t.Fatalf("code %q, want %q", c, theauth.CodeSignupClosed)
		}
		if a.SetupToken() != "" {
			t.Fatal("setup token still readable after a user exists")
		}
		// No credential was created for the seeded user.
		u, err := store.UserByEmail(context.Background(), email)
		if err != nil || u == nil {
			t.Fatalf("seeded user missing: %v", err)
		}
		if hash, err := store.UserPasswordHashByID(context.Background(), u.ID); err != nil || hash != "" {
			t.Fatalf("seeded user has a password credential (err %v)", err)
		}
	})

	t.Run("restart with a seeded user issues no setup token", func(t *testing.T) {
		a, store := hardenedAuth(t, func(c *theauth.Config) {
			c.Bootstrap = &theauth.BootstrapConfig{SetupToken: "s3cret-token", SuppressSetupTokenLog: true}
		})
		if _, err := a.CreateUser(context.Background(), theauth.CreateUserInput{Email: email}); err != nil {
			t.Fatal(err)
		}
		b, err := theauth.New(theauth.Config{
			Storage: store, BaseURL: "http://localhost", EncryptionKey: make([]byte, 32),
			Bootstrap: &theauth.BootstrapConfig{SetupToken: "s3cret-token", SuppressSetupTokenLog: true},
		})
		if err != nil {
			t.Fatal(err)
		}
		defer b.Close()
		if b.SetupToken() != "" {
			t.Fatal("token issued although a user exists")
		}
		if res := signup(t, b, email, "s3cret-token"); res.StatusCode != http.StatusForbidden {
			t.Fatalf("status %d, want 403", res.StatusCode)
		}
	})
}
