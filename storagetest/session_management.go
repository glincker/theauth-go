package storagetest

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glincker/theauth-go"
)

// SessionManagementSuiteStorage is the storage RunSessionManagement needs.
type SessionManagementSuiteStorage interface {
	theauth.UserStorage
	theauth.SessionStorage
	theauth.SessionManagementStorage
	theauth.SessionLinkStorage
}

// RunSessionManagement runs the session list, last-seen, bulk revoke,
// elevation and session link contract tests.
func RunSessionManagement(t *testing.T, store SessionManagementSuiteStorage) {
	t.Helper()
	t.Run("SessionManagement", func(t *testing.T) { testSessionManagement(t, store) })
	t.Run("SessionLinks", func(t *testing.T) { testSessionLinks(t, store) })
}

func mkUser(t *testing.T, store theauth.UserStorage, email string) theauth.ULID {
	t.Helper()
	id := newID()
	if _, err := store.CreateUser(context.Background(), theauth.User{ID: id, Email: email, CreatedAt: time.Now()}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	return id
}

func mkSession(t *testing.T, store theauth.SessionStorage, user theauth.ULID, tag string, created time.Time, ttl time.Duration, credential string) theauth.Session {
	t.Helper()
	s, err := store.CreateSession(context.Background(), theauth.Session{
		ID: newID(), UserID: user, TokenHash: sha256Hash([]byte(tag)),
		CreatedAt: created, LastSeenAt: created, ExpiresAt: created.Add(ttl), CredentialID: credential,
	})
	if err != nil {
		t.Fatalf("CreateSession(%s): %v", tag, err)
	}
	return s
}

func testSessionManagement(t *testing.T, store SessionManagementSuiteStorage) {
	ctx := context.Background()
	now := time.Now().Truncate(time.Millisecond)
	owner := mkUser(t, store, "sm-owner@storagetest.example")
	other := mkUser(t, store, "sm-other@storagetest.example")

	t.Run("ListUserSessionsFiltersAndOrders", func(t *testing.T) {
		older := mkSession(t, store, owner, "sm-list-old", now.Add(-2*time.Minute), time.Hour, "")
		newer := mkSession(t, store, owner, "sm-list-new", now.Add(-time.Minute), time.Hour, "")
		expired := mkSession(t, store, owner, "sm-list-exp", now.Add(-3*time.Hour), time.Hour, "")
		revoked := mkSession(t, store, owner, "sm-list-rev", now, time.Hour, "")
		mkSession(t, store, other, "sm-list-other", now, time.Hour, "")
		if err := store.RevokeSession(ctx, revoked.ID); err != nil {
			t.Fatal(err)
		}
		got, err := store.ListUserSessions(ctx, owner)
		if err != nil {
			t.Fatalf("ListUserSessions: %v", err)
		}
		ids := map[theauth.ULID]bool{}
		for _, s := range got {
			ids[s.ID] = true
			if s.UserID != owner {
				t.Fatalf("foreign session %s listed", s.ID)
			}
		}
		if !ids[older.ID] || !ids[newer.ID] || ids[expired.ID] || ids[revoked.ID] {
			t.Fatalf("unexpected membership: %v", ids)
		}
		var iNew, iOld = -1, -1
		for i, s := range got {
			switch s.ID {
			case newer.ID:
				iNew = i
			case older.ID:
				iOld = i
			}
		}
		if iNew > iOld {
			t.Fatalf("want newest first, got new@%d old@%d", iNew, iOld)
		}
	})

	t.Run("TouchIsMonotonic", func(t *testing.T) {
		s := mkSession(t, store, owner, "sm-touch", now.Add(-time.Hour), 2*time.Hour, "")
		later := now.Add(-time.Minute)
		if err := store.TouchSession(ctx, s.ID, later); err != nil {
			t.Fatalf("TouchSession: %v", err)
		}
		if err := store.TouchSession(ctx, s.ID, now.Add(-30*time.Minute)); err != nil {
			t.Fatalf("TouchSession older: %v", err)
		}
		got, err := store.SessionByID(ctx, s.ID)
		if err != nil {
			t.Fatal(err)
		}
		if !got.LastSeenAt.Equal(later) {
			t.Fatalf("LastSeenAt = %v, want %v", got.LastSeenAt, later)
		}
		if err := store.TouchSession(ctx, newID(), now); !errors.Is(err, theauth.ErrStorageNotFound) {
			t.Fatalf("unknown id: want ErrStorageNotFound, got %v", err)
		}
	})

	t.Run("RevokeOtherUserSessions", func(t *testing.T) {
		u := mkUser(t, store, "sm-revoke-others@storagetest.example")
		keep := mkSession(t, store, u, "sm-ro-keep", now, time.Hour, "")
		a := mkSession(t, store, u, "sm-ro-a", now, time.Hour, "")
		b := mkSession(t, store, u, "sm-ro-b", now, time.Hour, "")
		foreign := mkSession(t, store, other, "sm-ro-foreign", now, time.Hour, "")
		n, err := store.RevokeOtherUserSessions(ctx, u, keep.ID)
		if err != nil || n != 2 {
			t.Fatalf("RevokeOtherUserSessions = %d, %v; want 2, nil", n, err)
		}
		for _, id := range []theauth.ULID{a.ID, b.ID} {
			if s, _ := store.SessionByID(ctx, id); s == nil || s.RevokedAt == nil {
				t.Fatalf("session %s not revoked", id)
			}
		}
		for _, id := range []theauth.ULID{keep.ID, foreign.ID} {
			if s, _ := store.SessionByID(ctx, id); s == nil || s.RevokedAt != nil {
				t.Fatalf("session %s must stay live", id)
			}
		}
		if n, _ := store.RevokeOtherUserSessions(ctx, u, keep.ID); n != 0 {
			t.Fatalf("second call revoked %d, want 0", n)
		}
	})

	t.Run("RevokeSessionsByCredential", func(t *testing.T) {
		bound := mkSession(t, store, owner, "sm-cred-1", now, time.Hour, "cred-A")
		bound2 := mkSession(t, store, other, "sm-cred-2", now, time.Hour, "cred-A")
		unrelated := mkSession(t, store, owner, "sm-cred-3", now, time.Hour, "cred-B")
		n, err := store.RevokeSessionsByCredential(ctx, "cred-A")
		if err != nil || n != 2 {
			t.Fatalf("RevokeSessionsByCredential = %d, %v; want 2, nil", n, err)
		}
		for _, id := range []theauth.ULID{bound.ID, bound2.ID} {
			if s, _ := store.SessionByID(ctx, id); s == nil || s.RevokedAt == nil {
				t.Fatalf("session %s not revoked", id)
			}
		}
		if s, _ := store.SessionByID(ctx, unrelated.ID); s == nil || s.RevokedAt != nil {
			t.Fatal("unrelated credential session revoked")
		}
		got, _ := store.SessionByID(ctx, unrelated.ID)
		if got.CredentialID != "cred-B" {
			t.Fatalf("CredentialID = %q, want cred-B", got.CredentialID)
		}
	})

	t.Run("SetSessionElevatedUntil", func(t *testing.T) {
		s := mkSession(t, store, owner, "sm-elev", now, time.Hour, "")
		until := now.Add(5 * time.Minute)
		if err := store.SetSessionElevatedUntil(ctx, s.ID, &until); err != nil {
			t.Fatal(err)
		}
		got, _ := store.SessionByID(ctx, s.ID)
		if got.ElevatedUntil == nil || !got.ElevatedUntil.Equal(until) {
			t.Fatalf("ElevatedUntil = %v, want %v", got.ElevatedUntil, until)
		}
		if err := store.SetSessionElevatedUntil(ctx, s.ID, nil); err != nil {
			t.Fatal(err)
		}
		got, _ = store.SessionByID(ctx, s.ID)
		if got.ElevatedUntil != nil {
			t.Fatalf("ElevatedUntil = %v, want nil", got.ElevatedUntil)
		}
		if err := store.SetSessionElevatedUntil(ctx, newID(), &until); !errors.Is(err, theauth.ErrStorageNotFound) {
			t.Fatalf("unknown id: want ErrStorageNotFound, got %v", err)
		}
	})
}

func testSessionLinks(t *testing.T, store SessionManagementSuiteStorage) {
	ctx := context.Background()
	now := time.Now()
	user := mkUser(t, store, "sl-owner@storagetest.example")
	mk := func(tag string, ttl time.Duration) theauth.SessionLink {
		l := theauth.SessionLink{
			ID: newID(), UserID: user, TokenHash: sha256Hash([]byte(tag)),
			CredentialID: "cred-" + tag, SessionTTL: time.Hour, CreatedAt: now, ExpiresAt: now.Add(ttl),
		}
		if err := store.CreateSessionLink(ctx, l); err != nil {
			t.Fatalf("CreateSessionLink: %v", err)
		}
		return l
	}

	t.Run("ConsumeOnce", func(t *testing.T) {
		l := mk("once", time.Minute)
		got, err := store.ConsumeSessionLink(ctx, l.TokenHash, now)
		if err != nil {
			t.Fatalf("ConsumeSessionLink: %v", err)
		}
		if got.UserID != user || got.CredentialID != l.CredentialID || got.SessionTTL != time.Hour {
			t.Fatalf("link fields not round-tripped: %+v", got)
		}
		if _, err := store.ConsumeSessionLink(ctx, l.TokenHash, now); !errors.Is(err, theauth.ErrStorageNotFound) {
			t.Fatalf("second consume: want ErrStorageNotFound, got %v", err)
		}
	})

	t.Run("ExpiredAndUnknown", func(t *testing.T) {
		l := mk("expired", time.Minute)
		if _, err := store.ConsumeSessionLink(ctx, l.TokenHash, now.Add(2*time.Minute)); !errors.Is(err, theauth.ErrStorageNotFound) {
			t.Fatalf("expired: want ErrStorageNotFound, got %v", err)
		}
		if _, err := store.ConsumeSessionLink(ctx, sha256Hash([]byte("nope")), now); !errors.Is(err, theauth.ErrStorageNotFound) {
			t.Fatalf("unknown: want ErrStorageNotFound, got %v", err)
		}
	})

	t.Run("ConcurrentConsumeHasOneWinner", func(t *testing.T) {
		l := mk("race", time.Minute)
		var wins atomic.Int32
		var wg sync.WaitGroup
		for i := 0; i < 16; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := store.ConsumeSessionLink(ctx, l.TokenHash, now); err == nil {
					wins.Add(1)
				}
			}()
		}
		wg.Wait()
		if wins.Load() != 1 {
			t.Fatalf("winners = %d, want 1", wins.Load())
		}
	})
}
