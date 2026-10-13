package session_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2/internal/models"
	"github.com/glincker/theauth-go/v2/internal/session"
)

type gateFunc func(ctx context.Context, userID models.ULID) error

func (f gateFunc) CheckSignin(ctx context.Context, userID models.ULID) error { return f(ctx, userID) }

func capSvc(t *testing.T, max int, mode string) (*session.Service, models.User, func() int) {
	t.Helper()
	svc, store, user := setup(t)
	svc.SetCap(session.Cap{Max: max, Mode: mode, Lister: store, Revoker: store})
	live := func() int {
		rows, err := store.ListUserSessions(context.Background(), user.ID)
		if err != nil {
			t.Fatal(err)
		}
		return len(rows)
	}
	return svc, user, live
}

func TestCapEvictOldest(t *testing.T) {
	svc, user, live := capSvc(t, 2, session.OverflowEvictOldest)
	ctx := context.Background()
	tok1, _, err := svc.Issue(ctx, user, "ua", "1.1.1.1")
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Millisecond)
	tok2, _, _ := svc.Issue(ctx, user, "ua", "1.1.1.1")
	time.Sleep(2 * time.Millisecond)
	tok3, _, err := svc.Issue(ctx, user, "ua", "1.1.1.1")
	if err != nil {
		t.Fatalf("third issue must evict, got %v", err)
	}
	if got := live(); got != 2 {
		t.Fatalf("live sessions = %d, want 2", got)
	}
	if _, _, err := svc.Validate(ctx, tok1); err == nil {
		t.Fatal("oldest session must be revoked")
	}
	for _, tok := range []string{tok2, tok3} {
		if _, _, err := svc.Validate(ctx, tok); err != nil {
			t.Fatalf("newer session must survive: %v", err)
		}
	}
}

func TestCapReject(t *testing.T) {
	svc, user, live := capSvc(t, 1, session.OverflowReject)
	ctx := context.Background()
	tok1, _, err := svc.Issue(ctx, user, "ua", "1.1.1.1")
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = svc.Issue(ctx, user, "ua", "1.1.1.1")
	var te *models.TheAuthError
	if !errors.As(err, &te) || te.Code != models.CodeSessionLimit {
		t.Fatalf("err = %v, want %s", err, models.CodeSessionLimit)
	}
	if live() != 1 {
		t.Fatalf("a rejected sign-in must not create a session")
	}
	if _, _, err := svc.Validate(ctx, tok1); err != nil {
		t.Fatalf("existing session must stay valid: %v", err)
	}
	// Probe sessions skip the cap.
	if _, _, err := svc.Issue(session.WithoutLimits(ctx), user, "ua", "1.1.1.1"); err != nil {
		t.Fatalf("WithoutLimits issue: %v", err)
	}
}

func TestCapIgnoresPendingAndExcluded(t *testing.T) {
	svc, store, user := setup(t)
	svc.SetCap(session.Cap{Max: 1, Mode: session.OverflowReject, Lister: store, Revoker: store})
	ctx := context.Background()
	pending, err := store.CreateSessionWithAuthLevel(ctx, models.Session{
		ID: models.ULID{1}, UserID: user.ID, TokenHash: []byte("p"), CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour), AuthLevel: models.AuthLevelPending2FA,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.EnforceCap(ctx, user.ID, models.ULID{}); err != nil {
		t.Fatalf("a pending session must not count: %v", err)
	}
	if _, _, err := svc.Issue(ctx, user, "ua", "ip"); err != nil {
		t.Fatal(err)
	}
	if err := svc.EnforceCap(ctx, user.ID, models.ULID{}); err == nil {
		t.Fatal("cap must reject once a full session exists")
	}
	_ = pending
}

func TestAccountGateBlocksIssue(t *testing.T) {
	svc, _, user := setup(t)
	want := models.NewError(models.CodePasswordChangeRequired, "change it", nil)
	svc.SetAccountGate(gateFunc(func(context.Context, models.ULID) error { return want }))
	_, _, err := svc.Issue(context.Background(), user, "ua", "ip")
	if !errors.Is(err, want) {
		t.Fatalf("err = %v, want gate error", err)
	}
	svc.SetAccountGate(gateFunc(func(context.Context, models.ULID) error { return nil }))
	if _, _, err := svc.Issue(context.Background(), user, "ua", "ip"); err != nil {
		t.Fatalf("open gate: %v", err)
	}
}
