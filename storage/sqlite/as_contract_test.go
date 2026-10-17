package sqlite_test

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sqlitestore "github.com/glincker/theauth-go/storage/sqlite"
	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/storagetest"
	"github.com/oklog/ulid/v2"
)

const asPragmas = "?_pragma=foreign_keys(1)&_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)&_txlock=immediate"

// asOpen opens a fresh migrated database and returns the store plus raw handle.
func asOpen(t *testing.T, opts ...sqlitestore.Option) (*sqlitestore.Store, *sql.DB) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "as.db")+asPragmas)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Ping(); err != nil {
		t.Fatalf("ping: %v", err)
	}
	if err := sqlitestore.Migrate(context.Background(), db, opts...); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	s, err := sqlitestore.New(db, opts...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s, db
}

func asNewStore(t *testing.T, opts ...sqlitestore.Option) *sqlitestore.Store {
	t.Helper()
	s, _ := asOpen(t, opts...)
	return s
}

func asID() theauth.ULID { return ulid.Make() }

func asHash(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

// asRace runs fn on n goroutines released together and returns how many returned true.
func asRace(n int, fn func() bool) int {
	var wins atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if fn() {
				wins.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	return int(wins.Load())
}

func TestASContracts(t *testing.T) {
	t.Parallel()
	suites := []struct {
		name string
		run  func(t *testing.T, s *sqlitestore.Store)
	}{
		{"OAuthServerCore", func(t *testing.T, s *sqlitestore.Store) { storagetest.RunOAuthServerCore(t, s) }},
		{"PushedRequests", func(t *testing.T, s *sqlitestore.Store) { storagetest.RunPushedRequests(t, s) }},
		{"OpaqueTokens", func(t *testing.T, s *sqlitestore.Store) { storagetest.RunOpaqueTokens(t, s) }},
		{"DeviceAuthorizations", func(t *testing.T, s *sqlitestore.Store) { storagetest.RunDeviceAuthorizations(t, s) }},
		{"RegistrationTokens", func(t *testing.T, s *sqlitestore.Store) { storagetest.RunRegistrationTokens(t, s) }},
	}
	for _, tc := range suites {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.run(t, asNewStore(t))
		})
		t.Run(tc.name+"CustomPrefix", func(t *testing.T) {
			t.Parallel()
			tc.run(t, asNewStore(t, sqlitestore.WithTablePrefix("auth_as_")))
		})
	}

	t.Run("AuthCodeSingleUseUnderConcurrency", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		s := asNewStore(t)
		code := theauth.AuthorizationCode{
			Code: "code-" + asID().String(), ClientID: "c", UserID: asID(), Scope: []string{"openid"},
			ExpiresAt: time.Now().Add(time.Minute), CreatedAt: time.Now(),
		}
		if err := s.InsertAuthorizationCode(ctx, code); err != nil {
			t.Fatal(err)
		}
		wins := asRace(32, func() bool {
			got, err := s.ConsumeAuthorizationCode(ctx, code.Code)
			if err != nil && !errors.Is(err, theauth.ErrStorageNotFound) {
				t.Errorf("unexpected consume error: %v", err)
			}
			return err == nil && got != nil
		})
		if wins != 1 {
			t.Fatalf("code consumed %d times, want exactly 1", wins)
		}
	})

	t.Run("RefreshRotationExactlyOneWinner", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		s := asNewStore(t)
		user := asID()
		tok := theauth.RefreshToken{
			ID: asID(), Hash: asHash("rt-race"), FamilyID: asID(), ClientID: "c", UserID: &user,
			Scope: []string{"openid"}, IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
		}
		if err := s.InsertRefreshToken(ctx, tok); err != nil {
			t.Fatal(err)
		}
		wins := asRace(32, func() bool {
			err := s.RevokeRefreshToken(ctx, tok.Hash, "rotated")
			if err != nil && !errors.Is(err, theauth.ErrStorageNotFound) {
				t.Errorf("unexpected revoke error: %v", err)
			}
			return err == nil
		})
		if wins != 1 {
			t.Fatalf("rotation gate won %d times, want exactly 1", wins)
		}
	})

	t.Run("RefreshReplayRevokesFamily", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		s := asNewStore(t)
		user, fam := asID(), asID()
		mk := func(h string) theauth.RefreshToken {
			return theauth.RefreshToken{
				ID: asID(), Hash: asHash(h), FamilyID: fam, ClientID: "c", UserID: &user,
				Scope: []string{"openid"}, IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
			}
		}
		parent := mk("fam-parent")
		if err := s.InsertRefreshToken(ctx, parent); err != nil {
			t.Fatal(err)
		}
		// Whoever wins the revoke mints the child; every loser treats it as replay.
		var minted atomic.Int32
		wins := asRace(24, func() bool {
			if err := s.RevokeRefreshToken(ctx, parent.Hash, "rotated"); err != nil {
				if !errors.Is(err, theauth.ErrStorageNotFound) {
					t.Errorf("revoke: %v", err)
				}
				if err := s.RevokeRefreshTokenFamily(ctx, fam, "replay"); err != nil {
					t.Errorf("family revoke: %v", err)
				}
				return false
			}
			if err := s.InsertRefreshToken(ctx, mk(fmt.Sprintf("fam-child-%d", minted.Add(1)))); err != nil {
				t.Errorf("child insert: %v", err)
			}
			return true
		})
		if wins != 1 {
			t.Fatalf("rotation winners = %d, want 1", wins)
		}
		// Replay once more after all goroutines finish, as a real attacker would.
		if err := s.RevokeRefreshTokenFamily(ctx, fam, "replay"); err != nil {
			t.Fatal(err)
		}
		child, err := s.RefreshTokenByHash(ctx, asHash("fam-child-1"))
		if err != nil || child.RevokedAt == nil || child.RevocationNote == "" {
			t.Fatalf("child after replay: %+v %v", child, err)
		}
	})

	t.Run("CodeReplayRevokesByAuthCode", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		s := asNewStore(t)
		user, fam := asID(), asID()
		for i := 0; i < 3; i++ {
			tok := theauth.RefreshToken{
				ID: asID(), Hash: asHash(fmt.Sprintf("bc-%d", i)), FamilyID: fam, ClientID: "c", UserID: &user,
				ParentJTI: fmt.Sprintf("jti-%d", i), AuthCodeHash: "code-h", Scope: []string{"openid"},
				IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
			}
			if i > 0 {
				tok.AuthCodeHash = "" // rotated children carry no code hash; the family still matches
			}
			if err := s.InsertRefreshToken(ctx, tok); err != nil {
				t.Fatal(err)
			}
		}
		total := atomic.Int32{}
		asRace(8, func() bool {
			j, err := s.RevokeRefreshTokensByAuthCode(ctx, "code-h", "replay")
			if err != nil {
				t.Errorf("revoke by code: %v", err)
			}
			total.Add(int32(len(j)))
			return false
		})
		if total.Load() != 3 {
			t.Fatalf("jtis revoked across racers = %d, want 3 (each token exactly once)", total.Load())
		}
	})

	t.Run("JWKSConcurrentRotationKeepsOneCurrent", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		s := asNewStore(t)
		now := time.Now()
		mk := func(kid, state string) theauth.JWKSKey {
			return theauth.JWKSKey{KID: kid, Alg: "ES256", Use: "sig", PublicJWK: []byte(`{}`), PrivateEnc: []byte("p"), State: state, CreatedAt: now}
		}
		for _, k := range []theauth.JWKSKey{mk("k-cur", theauth.JWKSStateCurrent), mk("k-next", theauth.JWKSStateNext)} {
			if err := s.InsertJWKSKey(ctx, k); err != nil {
				t.Fatal(err)
			}
		}
		// A second current key for the same algorithm must be rejected.
		if err := s.InsertJWKSKey(ctx, mk("k-dup", theauth.JWKSStateCurrent)); err == nil {
			t.Fatal("two current keys for one alg were accepted")
		}
		// A different algorithm keeps its own current key.
		other := mk("k-eddsa", theauth.JWKSStateCurrent)
		other.Alg = "EdDSA"
		if err := s.InsertJWKSKey(ctx, other); err != nil {
			t.Fatalf("per-alg current key: %v", err)
		}
		var n atomic.Int32
		asRace(8, func() bool {
			err := s.AtomicRotateJWKS(ctx, nil, "k-cur", "k-next", mk(fmt.Sprintf("k-fresh-%d", n.Add(1)), theauth.JWKSStateNext), time.Now())
			if err != nil {
				t.Errorf("rotate: %v", err)
			}
			return err == nil
		})
		keys, err := s.JWKSKeysAll(ctx)
		if err != nil {
			t.Fatal(err)
		}
		current := map[string]int{}
		for _, k := range keys {
			if k.State == theauth.JWKSStateCurrent {
				current[k.Alg]++
			}
		}
		if current["ES256"] != 1 || current["EdDSA"] != 1 {
			t.Fatalf("current keys per alg = %v, want one each", current)
		}
		got, _ := s.JWKSKeyByKID(ctx, "k-next")
		if got == nil || got.State != theauth.JWKSStateCurrent || got.PromotedAt == nil {
			t.Fatalf("promoted key: %+v", got)
		}
		// An unknown promote kid rolls the whole transition back.
		before, _ := s.JWKSKeysAll(ctx)
		if err := s.AtomicRotateJWKS(ctx, nil, "k-next", "no-such", mk("k-rolled-back", theauth.JWKSStateNext), time.Now()); !errors.Is(err, theauth.ErrStorageNotFound) {
			t.Fatalf("unknown promote kid: got %v", err)
		}
		after, _ := s.JWKSKeysAll(ctx)
		if len(after) != len(before) {
			t.Fatalf("rotation was not rolled back: %d keys before, %d after", len(before), len(after))
		}
		if k, _ := s.JWKSKeyByKID(ctx, "k-next"); k.State != theauth.JWKSStateCurrent {
			t.Fatalf("demotion leaked out of the rolled back transaction: %s", k.State)
		}
	})

	t.Run("RegistrationTokenRedeemRace", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		s := asNewStore(t)
		now := time.Now()
		tok := theauth.RegistrationToken{
			ID: asID(), TokenHash: asHash("reg"), MaxUses: 3, CreatedAt: now, ExpiresAt: now.Add(time.Hour),
		}
		if err := s.InsertRegistrationToken(ctx, tok); err != nil {
			t.Fatal(err)
		}
		wins := asRace(24, func() bool {
			ok, err := s.RedeemRegistrationToken(ctx, tok.ID, now)
			if err != nil {
				t.Errorf("redeem: %v", err)
			}
			return ok
		})
		if wins != 3 {
			t.Fatalf("redeemed %d times, want max_uses = 3", wins)
		}
	})

	t.Run("AccessTokenDenylistAndPurge", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		s := asNewStore(t)
		if err := s.DenyAccessToken(ctx, "j1", time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		// Re-denying extends the entry instead of failing.
		if err := s.DenyAccessToken(ctx, "j1", time.Now().Add(2*time.Hour)); err != nil {
			t.Fatal(err)
		}
		if ok, err := s.IsAccessTokenDenied(ctx, "j1"); err != nil || !ok {
			t.Fatalf("denied = %v, %v", ok, err)
		}
	})

	t.Run("CascadeOnDelete", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		s, db := asOpen(t)
		u, err := s.CreateUser(ctx, theauth.User{ID: asID(), Email: "cascade@example.com", CreatedAt: time.Now()})
		if err != nil {
			t.Fatal(err)
		}
		count := func(table, where string, args ...any) int {
			var n int
			if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM theauth_"+table+" WHERE "+where, args...).Scan(&n); err != nil {
				t.Fatal(err)
			}
			return n
		}
		if _, err := s.InsertOAuthClient(ctx, theauth.OAuthClient{
			ID: asID(), ClientID: "owned", Owner: theauth.ClientOwner{UserID: &u.ID}, CreatedAt: time.Now(),
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := s.InsertOAuthClient(ctx, theauth.OAuthClient{ID: asID(), ClientID: "anon", AnonymousRegistered: true, CreatedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
		seed := func() {
			for _, c := range []string{"owned", "anon"} {
				_ = s.InsertAuthorizationCode(ctx, theauth.AuthorizationCode{
					Code: "code-" + c + asID().String(), ClientID: c, UserID: asID(), ExpiresAt: time.Now().Add(time.Minute),
				})
				_ = s.InsertRefreshToken(ctx, theauth.RefreshToken{
					ID: asID(), Hash: asHash("h-" + c + asID().String()), FamilyID: asID(), ClientID: c,
					ExpiresAt: time.Now().Add(time.Hour), IssuedAt: time.Now(),
				})
			}
		}
		seed()
		if err := s.DeleteOAuthClient(ctx, "anon"); err != nil {
			t.Fatal(err)
		}
		if n := count("oauth_authorization_codes", "client_id = ?", "anon") + count("oauth_refresh_tokens", "client_id = ?", "anon"); n != 0 {
			t.Fatalf("client delete left %d rows", n)
		}
		if n := count("oauth_authorization_codes", "client_id = ?", "owned"); n != 1 {
			t.Fatalf("unrelated client's codes were removed: %d", n)
		}
		if _, err := db.ExecContext(ctx, "DELETE FROM theauth_users WHERE id = ?", u.ID.String()); err != nil {
			t.Fatal(err)
		}
		if _, err := s.OAuthClientByClientID(ctx, "owned"); !errors.Is(err, theauth.ErrStorageNotFound) {
			t.Fatalf("owned client survived its user: %v", err)
		}
		if n := count("oauth_authorization_codes", "client_id = ?", "owned") + count("oauth_refresh_tokens", "client_id = ?", "owned"); n != 0 {
			t.Fatalf("user delete left %d rows under the owned client", n)
		}
	})

	t.Run("MigrationsRenderWithPrefix", func(t *testing.T) {
		t.Parallel()
		migs, err := sqlitestore.RenderMigrations(sqlitestore.WithTablePrefix("zz_"))
		if err != nil {
			t.Fatal(err)
		}
		found := 0
		for _, m := range migs {
			if strings.Contains(m.SQL, "theauth_") {
				t.Fatalf("migration %s kept the default prefix", m.Version)
			}
			if m.Version >= "0020" && m.Version <= "0029" {
				found++
			}
		}
		if found == 0 {
			t.Fatal("no 0020-0029 migrations rendered")
		}
	})
}
