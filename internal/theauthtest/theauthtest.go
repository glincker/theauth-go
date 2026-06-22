// Package theauthtest provides shared test helpers for building TheAuth
// instances and creating users in tests across internal packages. All
// exported helpers require a *testing.T or testing.TB and register
// cleanup functions automatically.
//
// Import this package only in _test.go files.
package theauthtest

import (
	"context"
	"testing"
	"time"

	theauth "github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/internal/ulid"
	"github.com/glincker/theauth-go/storage/memory"
)

// NewTestAuth constructs a minimal TheAuth backed by an in-memory store.
// Session and magic-link TTLs are set to 1 hour / 15 minutes respectively.
// Rate limits are raised to 100 per bucket so multi-step flows do not trip
// limits unless a test is specifically probing the rate-limiter behavior.
// The caller must not call a.Close(); the t.Cleanup hook handles that.
func NewTestAuth(t *testing.T) (*theauth.TheAuth, *memory.Store) {
	t.Helper()
	store := memory.New()
	a, err := theauth.New(theauth.Config{
		Storage:           store,
		BaseURL:           "http://localhost",
		SessionTTL:        time.Hour,
		MagicLinkTTL:      15 * time.Minute,
		RateLimitPerIP:    100,
		RateLimitPerEmail: 100,
	})
	if err != nil {
		t.Fatalf("theauthtest.NewTestAuth: %v", err)
	}
	t.Cleanup(a.Close)
	return a, store
}

// NewUser inserts a user with the given email directly into store and
// returns the created row. The user has a fresh ULID and a creation time
// of now. It is a fatal test error if the insert fails.
func NewUser(t *testing.T, store *memory.Store, email string) theauth.User {
	t.Helper()
	u, err := store.CreateUser(context.Background(), theauth.User{
		ID:        ulid.New(),
		Email:     email,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("theauthtest.NewUser(%q): %v", email, err)
	}
	return u
}
