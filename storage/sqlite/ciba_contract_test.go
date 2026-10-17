package sqlite_test

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sqlitestore "github.com/glincker/theauth-go/storage/sqlite"
	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/storagetest"
	"github.com/oklog/ulid/v2"
)

const cibaPragmas = "?_pragma=foreign_keys(1)&_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)&_txlock=immediate"

func cibaStore(t *testing.T, opts ...sqlitestore.Option) *sqlitestore.Store {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "ciba.db")+cibaPragmas)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Ping(); err != nil {
		t.Fatalf("ping: %v", err)
	}
	if err := sqlitestore.Migrate(context.Background(), db, opts...); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	s, err := sqlitestore.New(db, opts...)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	return s
}

func cibaUser(t *testing.T, s *sqlitestore.Store) theauth.ULID {
	t.Helper()
	u, err := s.CreateUser(context.Background(), theauth.User{ID: ulid.Make(), Email: ulid.Make().String() + "@ciba.example", CreatedAt: time.Now()})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	return u.ID
}

func cibaReq(id string) theauth.BackchannelRequest {
	now := time.Now().UTC()
	return theauth.BackchannelRequest{
		AuthReqID: id, ClientID: "c1", Scope: []string{"openid"}, Status: theauth.BackchannelStatusPending,
		PollInterval: 5, ExpiresAt: now.Add(time.Minute), CreatedAt: now,
	}
}

func TestCIBAAndIdentityContracts(t *testing.T) {
	t.Parallel()
	suites := []struct {
		name string
		run  func(t *testing.T, s *sqlitestore.Store)
	}{
		{"CIBA", func(t *testing.T, s *sqlitestore.Store) {
			storagetest.RunCIBA(t, s, func(t *testing.T) theauth.ULID { return cibaUser(t, s) })
		}},
		{"Core", func(t *testing.T, s *sqlitestore.Store) { storagetest.RunCore(t, s) }},
		{"DeviceIdentity", func(t *testing.T, s *sqlitestore.Store) { storagetest.RunDeviceIdentity(t, s) }},
		{"Enterprise", func(t *testing.T, s *sqlitestore.Store) { storagetest.RunEnterprise(t, s) }},
		{"EnterpriseConstraints", func(t *testing.T, s *sqlitestore.Store) { storagetest.RunEnterpriseConstraints(t, s) }},
		{"RBAC", func(t *testing.T, s *sqlitestore.Store) { storagetest.RunRBAC(t, s) }},
	}
	for _, tc := range suites {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.run(t, cibaStore(t))
		})
	}
	t.Run("CIBACustomPrefix", func(t *testing.T) {
		t.Parallel()
		s := cibaStore(t, sqlitestore.WithTablePrefix("auth_x_"))
		storagetest.RunCIBA(t, s, func(t *testing.T) theauth.ULID { return cibaUser(t, s) })
	})

	t.Run("ConcurrentApproveExactlyOnce", func(t *testing.T) {
		t.Parallel()
		s := cibaStore(t)
		ctx := context.Background()
		if err := s.InsertBackchannelRequest(ctx, cibaReq("approve-once")); err != nil {
			t.Fatal(err)
		}
		const n = 16
		var wins, conflicts atomic.Int32
		var wg sync.WaitGroup
		for i := 0; i < n; i++ {
			uid := cibaUser(t, s)
			wg.Add(1)
			go func() {
				defer wg.Done()
				r := cibaReq("approve-once")
				r.Status = theauth.BackchannelStatusApproved
				r.UserID = &uid
				r.AccessToken = "at-" + uid.String()
				switch err := s.UpdateBackchannelRequest(ctx, r); {
				case err == nil:
					wins.Add(1)
				case errors.Is(err, sqlitestore.ErrBackchannelStateConflict):
					conflicts.Add(1)
				default:
					t.Errorf("unexpected error: %v", err)
				}
			}()
		}
		wg.Wait()
		if wins.Load() != 1 || conflicts.Load() != n-1 {
			t.Fatalf("wins=%d conflicts=%d", wins.Load(), conflicts.Load())
		}
		got, err := s.BackchannelRequestByID(ctx, "approve-once")
		if err != nil || got.UserID == nil || got.AccessToken != "at-"+got.UserID.String() {
			t.Fatalf("winner state inconsistent: %+v %v", got, err)
		}
	})

	t.Run("ApproveVersusDenyExactlyOnce", func(t *testing.T) {
		t.Parallel()
		s := cibaStore(t)
		ctx := context.Background()
		if err := s.InsertBackchannelRequest(ctx, cibaReq("race")); err != nil {
			t.Fatal(err)
		}
		var wins atomic.Int32
		var wg sync.WaitGroup
		for _, st := range []string{theauth.BackchannelStatusApproved, theauth.BackchannelStatusDenied} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				r := cibaReq("race")
				r.Status = st
				if err := s.UpdateBackchannelRequest(ctx, r); err == nil {
					wins.Add(1)
				}
			}()
		}
		wg.Wait()
		if wins.Load() != 1 {
			t.Fatalf("wins=%d", wins.Load())
		}
	})

	t.Run("ConcurrentRedeemExactlyOnce", func(t *testing.T) {
		t.Parallel()
		s := cibaStore(t)
		ctx := context.Background()
		r := cibaReq("redeem-once")
		if err := s.InsertBackchannelRequest(ctx, r); err != nil {
			t.Fatal(err)
		}
		if _, ok, err := s.RedeemBackchannelRequest(ctx, "redeem-once", time.Now()); err != nil || ok {
			t.Fatalf("pending redeemed: ok=%v err=%v", ok, err)
		}
		r.Status, r.AccessToken, r.RefreshToken = theauth.BackchannelStatusApproved, "at", "rt"
		if err := s.UpdateBackchannelRequest(ctx, r); err != nil {
			t.Fatal(err)
		}
		const n = 32
		var wins atomic.Int32
		var wg sync.WaitGroup
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				got, ok, err := s.RedeemBackchannelRequest(ctx, "redeem-once", time.Now())
				if err != nil {
					t.Errorf("redeem: %v", err)
					return
				}
				if ok {
					wins.Add(1)
					if got.AccessToken != "at" || got.RefreshToken != "rt" || got.Status != sqlitestore.BackchannelStatusConsumed {
						t.Errorf("winner payload: %+v", got)
					}
				}
			}()
		}
		wg.Wait()
		if wins.Load() != 1 {
			t.Fatalf("wins=%d, want 1", wins.Load())
		}
		if _, ok, _ := s.RedeemBackchannelRequest(ctx, "redeem-once", time.Now()); ok {
			t.Fatal("redeemed twice")
		}
	})

	t.Run("RedeemRejectsExpiredAndDenied", func(t *testing.T) {
		t.Parallel()
		s := cibaStore(t)
		ctx := context.Background()
		r := cibaReq("exp")
		r.Status = theauth.BackchannelStatusPending
		if err := s.InsertBackchannelRequest(ctx, r); err != nil {
			t.Fatal(err)
		}
		r.Status = theauth.BackchannelStatusApproved
		if err := s.UpdateBackchannelRequest(ctx, r); err != nil {
			t.Fatal(err)
		}
		if _, ok, err := s.RedeemBackchannelRequest(ctx, "exp", r.ExpiresAt.Add(time.Second)); err != nil || ok {
			t.Fatalf("expired redeemed: ok=%v err=%v", ok, err)
		}
		d := cibaReq("den")
		if err := s.InsertBackchannelRequest(ctx, d); err != nil {
			t.Fatal(err)
		}
		d.Status = theauth.BackchannelStatusDenied
		if err := s.UpdateBackchannelRequest(ctx, d); err != nil {
			t.Fatal(err)
		}
		if _, ok, _ := s.RedeemBackchannelRequest(ctx, "den", time.Now()); ok {
			t.Fatal("denied request redeemed")
		}
		if err := s.UpdateBackchannelRequest(ctx, d); !errors.Is(err, sqlitestore.ErrBackchannelStateConflict) {
			t.Fatalf("rewrite of terminal row: %v", err)
		}
	})

	t.Run("ExpirePending", func(t *testing.T) {
		t.Parallel()
		s := cibaStore(t)
		ctx := context.Background()
		for _, id := range []string{"e1", "e2"} {
			if err := s.InsertBackchannelRequest(ctx, cibaReq(id)); err != nil {
				t.Fatal(err)
			}
		}
		n, err := s.ExpireBackchannelRequests(ctx, time.Now().Add(time.Hour))
		if err != nil || n != 2 {
			t.Fatalf("expired %d, %v", n, err)
		}
		got, _ := s.BackchannelRequestByID(ctx, "e1")
		if got.Status != sqlitestore.BackchannelStatusExpired {
			t.Fatalf("status %q", got.Status)
		}
		if n, _ := s.ExpireBackchannelRequests(ctx, time.Now().Add(time.Hour)); n != 0 {
			t.Fatalf("second sweep changed %d", n)
		}
	})

	t.Run("DuplicateInsertFails", func(t *testing.T) {
		t.Parallel()
		s := cibaStore(t)
		ctx := context.Background()
		if err := s.InsertBackchannelRequest(ctx, cibaReq("dup")); err != nil {
			t.Fatal(err)
		}
		if err := s.InsertBackchannelRequest(ctx, cibaReq("dup")); err == nil {
			t.Fatal("duplicate accepted")
		}
	})

	t.Run("ConcurrentTouchKeepsRowConsistent", func(t *testing.T) {
		t.Parallel()
		s := cibaStore(t)
		ctx := context.Background()
		if err := s.InsertBackchannelRequest(ctx, cibaReq("touch")); err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		for i := 0; i < 16; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := s.TouchBackchannelPoll(ctx, "touch", time.Now(), 5+i); err != nil {
					t.Errorf("touch: %v", err)
				}
			}()
		}
		wg.Wait()
		got, err := s.BackchannelRequestByID(ctx, "touch")
		if err != nil || got.LastPollAt == nil || got.Status != theauth.BackchannelStatusPending {
			t.Fatalf("after touches: %+v %v", got, err)
		}
	})
}
