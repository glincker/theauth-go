package sqlite_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	sqlitestore "github.com/glincker/theauth-go/storage/sqlite"
	"github.com/glincker/theauth-go/v2"
)

// TestSessionsWithoutAuthColumns pins that hosts which upgraded the library
// but have not run migration 0034 keep working: sessions read and write with
// no auth record, and recording one reports a missing capability. Applying
// the migration afterwards turns the full behavior on for a new Store.
func TestSessionsWithoutAuthColumns(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := openDB(t)
	migs, err := sqlitestore.RenderMigrations()
	if err != nil {
		t.Fatal(err)
	}
	apply := func(keep func(version string) bool) {
		t.Helper()
		for _, m := range migs {
			if !keep(m.Version) {
				continue
			}
			if _, err := db.ExecContext(ctx, m.SQL); err != nil {
				t.Fatalf("apply %s: %v", m.Version, err)
			}
		}
	}
	apply(func(v string) bool { return v < "0034" })

	s, err := sqlitestore.New(db)
	if err != nil {
		t.Fatal(err)
	}
	u := mkUser(t, s, "legacy-auth@example.com")
	at := time.Now().Add(-time.Minute)
	sess, err := s.CreateSession(ctx, theauth.Session{
		ID: newID(), UserID: u.ID, TokenHash: []byte("legacy-auth"), ExpiresAt: time.Now().Add(time.Hour),
		AuthMethods: []string{"pwd"}, AuthTime: at,
	})
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if sess.AuthMethods != nil || !sess.AuthTime.IsZero() {
		t.Fatalf("created session has auth record %v %v", sess.AuthMethods, sess.AuthTime)
	}
	got, err := s.SessionByID(ctx, sess.ID)
	if err != nil || got.AuthMethods != nil || !got.AuthTime.IsZero() {
		t.Fatalf("SessionByID = %+v, %v", got, err)
	}
	byHash, err := s.SessionByTokenHash(ctx, []byte("legacy-auth"))
	if err != nil || byHash.ID != sess.ID {
		t.Fatalf("SessionByTokenHash = %+v, %v", byHash, err)
	}
	list, err := s.ListUserSessions(ctx, u.ID)
	if err != nil || len(list) != 1 || list[0].AuthMethods != nil || !list[0].AuthTime.IsZero() {
		t.Fatalf("ListUserSessions = %+v, %v", list, err)
	}
	if _, err := s.SweepExpired(ctx, time.Now()); err != nil {
		t.Fatalf("SweepExpired: %v", err)
	}
	if _, _, err := s.AppendSessionAuthMethods(ctx, sess.ID, []string{"otp"}, time.Now()); !errors.Is(err, theauth.ErrStorageMissingCapability) {
		t.Fatalf("AppendSessionAuthMethods err = %v, want ErrStorageMissingCapability", err)
	}

	apply(func(v string) bool { return strings.HasPrefix(v, "0034") })
	s2, err := sqlitestore.New(db)
	if err != nil {
		t.Fatal(err)
	}
	methods, when, err := s2.AppendSessionAuthMethods(ctx, sess.ID, []string{"pwd", "otp"}, at)
	if err != nil || len(methods) != 2 || when.IsZero() {
		t.Fatalf("AppendSessionAuthMethods after 0034 = %v %v %v", methods, when, err)
	}
	got, err = s2.SessionByID(ctx, sess.ID)
	if err != nil || len(got.AuthMethods) != 2 || got.AuthTime.IsZero() {
		t.Fatalf("SessionByID after 0034 = %+v, %v", got, err)
	}
	full, err := s2.CreateSession(ctx, theauth.Session{
		ID: newID(), UserID: u.ID, TokenHash: []byte("new-auth"), ExpiresAt: time.Now().Add(time.Hour),
		AuthMethods: []string{"pwd"}, AuthTime: at,
	})
	if err != nil || len(full.AuthMethods) != 1 || full.AuthTime.IsZero() {
		t.Fatalf("CreateSession after 0034 = %+v, %v", full, err)
	}
}
