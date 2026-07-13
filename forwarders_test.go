package theauth_test

import (
	"context"
	"testing"
	"time"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/internal/ulid"
)

func TestTheAuth_RevokeSession_Forwards(t *testing.T) {
	a, store := newTestAuth(t)
	ctx := context.Background()
	user, _ := store.CreateUser(ctx, theauth.User{ID: ulid.New(), Email: "revoke@v.com", CreatedAt: time.Now(), UpdatedAt: time.Now()})

	_, sess, err := theauth.IssueSessionForTest(a, ctx, user, "ua", "")
	if err != nil {
		t.Fatalf("IssueSessionForTest: %v", err)
	}

	if err := a.RevokeSession(ctx, sess.ID); err != nil {
		t.Fatalf("RevokeSession: %v", err)
	}
	got, err := a.SessionByID(ctx, sess.ID)
	if err != nil {
		t.Fatalf("SessionByID after revoke: %v", err)
	}
	if got.RevokedAt == nil {
		t.Error("expected RevokedAt to be set after RevokeSession")
	}
}

func TestTheAuth_RevokeUserSessions_Forwards(t *testing.T) {
	a, store := newTestAuth(t)
	ctx := context.Background()
	user, _ := store.CreateUser(ctx, theauth.User{ID: ulid.New(), Email: "revokeall@v.com", CreatedAt: time.Now(), UpdatedAt: time.Now()})

	_, sess, err := theauth.IssueSessionForTest(a, ctx, user, "ua", "")
	if err != nil {
		t.Fatalf("IssueSessionForTest: %v", err)
	}

	if err := a.RevokeUserSessions(ctx, user.ID); err != nil {
		t.Fatalf("RevokeUserSessions: %v", err)
	}
	got, err := a.SessionByID(ctx, sess.ID)
	if err != nil {
		t.Fatalf("SessionByID after revoke all: %v", err)
	}
	if got.RevokedAt == nil {
		t.Error("expected RevokedAt to be set after RevokeUserSessions")
	}
}

func TestTheAuth_SessionByID_NotFound(t *testing.T) {
	a, _ := newTestAuth(t)
	ctx := context.Background()

	if _, err := a.SessionByID(ctx, ulid.New()); err == nil {
		t.Error("expected error for unknown session id")
	}
}
