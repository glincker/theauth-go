package theauth_test

import (
	"context"
	"testing"
	"time"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/internal/ulid"
	"github.com/glincker/theauth-go/storage/memory"
)

func newTestAuth(t *testing.T) (*theauth.TheAuth, *memory.Store) {
	t.Helper()
	store := memory.New()
	a, err := theauth.New(theauth.Config{
		Storage:      store,
		BaseURL:      "http://localhost",
		SessionTTL:   time.Hour,
		MagicLinkTTL: 15 * time.Minute,
		// Test defaults: keep production-realistic ratios but raise headroom
		// so multi-step e2e flows don't trip the per-email limit while still
		// letting dedicated tests assert the 429 boundary.
		RateLimitPerIP:    100,
		RateLimitPerEmail: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	return a, store
}

func TestIssueAndValidateSession(t *testing.T) {
	a, store := newTestAuth(t)
	ctx := context.Background()
	user, _ := store.CreateUser(ctx, theauth.User{ID: ulid.New(), Email: "i@v.com", CreatedAt: time.Now(), UpdatedAt: time.Now()})

	token, sess, err := theauth.IssueSessionForTest(a, ctx, user, "ua", "")
	if err != nil {
		t.Fatal(err)
	}
	if token == "" || sess.ID.String() == "" {
		t.Fatal("issueSession returned empty")
	}

	gotSess, gotUser, err := theauth.ValidateSessionForTest(a, ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	if gotSess.ID != sess.ID {
		t.Fatal("session ID mismatch")
	}
	if gotUser.Email != "i@v.com" {
		t.Fatal("user email mismatch")
	}
}

func TestValidateSessionInvalidToken(t *testing.T) {
	a, _ := newTestAuth(t)
	_, _, err := theauth.ValidateSessionForTest(a, context.Background(), "bogus")
	if err == nil {
		t.Fatal("expected error for bogus token")
	}
}

func TestValidateSessionRevoked(t *testing.T) {
	a, store := newTestAuth(t)
	ctx := context.Background()
	user, _ := store.CreateUser(ctx, theauth.User{ID: ulid.New(), Email: "r@r.com", CreatedAt: time.Now(), UpdatedAt: time.Now()})
	token, sess, _ := theauth.IssueSessionForTest(a, ctx, user, "", "")
	_ = store.RevokeSession(ctx, sess.ID)

	_, _, err := theauth.ValidateSessionForTest(a, ctx, token)
	if err == nil {
		t.Fatal("expected error for revoked session")
	}
}
