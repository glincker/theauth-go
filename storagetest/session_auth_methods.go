package storagetest

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
)

// SessionAuthSuiteStorage is the storage RunSessionAuthMethods needs.
type SessionAuthSuiteStorage interface {
	theauth.UserStorage
	theauth.SessionStorage
	theauth.SessionAuthStorage
}

// RunSessionAuthMethods runs the session authentication record contract:
// the record round trips through CreateSession and every session read, a
// session without one reads as nil and zero, appends keep order without
// duplicates, advance AuthTime but never move it back, and concurrent
// appends lose nothing.
func RunSessionAuthMethods(t *testing.T, store SessionAuthSuiteStorage) {
	t.Helper()
	t.Run("SessionAuthMethods", func(t *testing.T) {
		t.Run("RoundTrip", func(t *testing.T) { testSessionAuthRoundTrip(t, store) })
		t.Run("Legacy", func(t *testing.T) { testSessionAuthLegacy(t, store) })
		t.Run("Append", func(t *testing.T) { testSessionAuthAppend(t, store) })
		t.Run("Concurrent", func(t *testing.T) { testSessionAuthConcurrent(t, store) })
	})
}

func authSession(t *testing.T, store SessionAuthSuiteStorage, tag string, methods []string, at time.Time) theauth.Session {
	t.Helper()
	user := mkUser(t, store, tag+"@example.test")
	now := time.Now().UTC().Truncate(time.Millisecond)
	s, err := store.CreateSession(context.Background(), theauth.Session{
		ID: newID(), UserID: user, TokenHash: sha256Hash([]byte(tag)),
		CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(time.Hour),
		AuthMethods: methods, AuthTime: at,
	})
	if err != nil {
		t.Fatalf("CreateSession(%s): %v", tag, err)
	}
	return s
}

func sameInstant(a, b time.Time) bool { return a.Sub(b).Abs() < time.Millisecond }

func testSessionAuthRoundTrip(t *testing.T, store SessionAuthSuiteStorage) {
	ctx := context.Background()
	at := time.Now().UTC().Add(-time.Minute).Truncate(time.Millisecond)
	s := authSession(t, store, "auth-roundtrip", []string{"pwd", "otp", "mfa"}, at)
	if !reflect.DeepEqual(s.AuthMethods, []string{"pwd", "otp", "mfa"}) || !sameInstant(s.AuthTime, at) {
		t.Fatalf("created = %v %v, want [pwd otp mfa] %v", s.AuthMethods, s.AuthTime, at)
	}
	byHash, err := store.SessionByTokenHash(ctx, s.TokenHash)
	if err != nil {
		t.Fatalf("SessionByTokenHash: %v", err)
	}
	byID, err := store.SessionByID(ctx, s.ID)
	if err != nil {
		t.Fatalf("SessionByID: %v", err)
	}
	for name, got := range map[string]*theauth.Session{"hash": byHash, "id": byID} {
		if !reflect.DeepEqual(got.AuthMethods, []string{"pwd", "otp", "mfa"}) || !sameInstant(got.AuthTime, at) {
			t.Errorf("by %s = %v %v, want [pwd otp mfa] %v", name, got.AuthMethods, got.AuthTime, at)
		}
	}
}

func testSessionAuthLegacy(t *testing.T, store SessionAuthSuiteStorage) {
	s := authSession(t, store, "auth-legacy", nil, time.Time{})
	got, err := store.SessionByID(context.Background(), s.ID)
	if err != nil {
		t.Fatalf("SessionByID: %v", err)
	}
	if len(got.AuthMethods) != 0 || !got.AuthTime.IsZero() {
		t.Fatalf("legacy session = %v %v, want no record", got.AuthMethods, got.AuthTime)
	}
}

func testSessionAuthAppend(t *testing.T, store SessionAuthSuiteStorage) {
	ctx := context.Background()
	t0 := time.Now().UTC().Add(-time.Hour).Truncate(time.Millisecond)
	s := authSession(t, store, "auth-append", []string{"pwd"}, t0)

	t1 := t0.Add(10 * time.Minute)
	methods, at, err := store.AppendSessionAuthMethods(ctx, s.ID, []string{"otp", "pwd", "mfa"}, t1)
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	if !reflect.DeepEqual(methods, []string{"pwd", "otp", "mfa"}) || !sameInstant(at, t1) {
		t.Fatalf("append = %v %v, want [pwd otp mfa] %v", methods, at, t1)
	}
	// An older timestamp never moves AuthTime back.
	_, at, err = store.AppendSessionAuthMethods(ctx, s.ID, []string{"hwk"}, t0)
	if err != nil {
		t.Fatalf("Append older: %v", err)
	}
	if !sameInstant(at, t1) {
		t.Errorf("AuthTime moved back to %v, want %v", at, t1)
	}
	got, err := store.SessionByID(ctx, s.ID)
	if err != nil {
		t.Fatalf("SessionByID: %v", err)
	}
	if !reflect.DeepEqual(got.AuthMethods, []string{"pwd", "otp", "mfa", "hwk"}) || !sameInstant(got.AuthTime, t1) {
		t.Errorf("stored = %v %v, want [pwd otp mfa hwk] %v", got.AuthMethods, got.AuthTime, t1)
	}

	// A session with no record gets one from the first append.
	legacy := authSession(t, store, "auth-append-legacy", nil, time.Time{})
	methods, at, err = store.AppendSessionAuthMethods(ctx, legacy.ID, []string{"otp"}, t1)
	if err != nil || !reflect.DeepEqual(methods, []string{"otp"}) || !sameInstant(at, t1) {
		t.Errorf("append to legacy = %v %v %v", methods, at, err)
	}

	if _, _, err := store.AppendSessionAuthMethods(ctx, newID(), []string{"pwd"}, t1); !errors.Is(err, theauth.ErrStorageNotFound) {
		t.Errorf("append unknown session err = %v, want ErrStorageNotFound", err)
	}
}

func testSessionAuthConcurrent(t *testing.T, store SessionAuthSuiteStorage) {
	ctx := context.Background()
	s := authSession(t, store, "auth-concurrent", []string{"pwd"}, time.Now().UTC())
	want := []string{"otp", "hwk", "swk", "mfa", "email", "fed", "sso", "x1"}
	var wg sync.WaitGroup
	errs := make(chan error, len(want))
	for _, m := range want {
		wg.Add(1)
		go func(m string) {
			defer wg.Done()
			_, _, err := store.AppendSessionAuthMethods(ctx, s.ID, []string{m}, time.Now())
			errs <- err
		}(m)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent append: %v", err)
		}
	}
	got, err := store.SessionByID(ctx, s.ID)
	if err != nil {
		t.Fatalf("SessionByID: %v", err)
	}
	have := map[string]bool{}
	for _, m := range got.AuthMethods {
		have[m] = true
	}
	for _, m := range append([]string{"pwd"}, want...) {
		if !have[m] {
			t.Errorf("method %q lost: stored %v", m, got.AuthMethods)
		}
	}
	if len(got.AuthMethods) != len(want)+1 {
		t.Errorf("stored %v, want %d distinct methods", got.AuthMethods, len(want)+1)
	}
}
