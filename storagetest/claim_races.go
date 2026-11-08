package storagetest

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/crypto"
	"github.com/glincker/theauth-go/v2/storage"
)

// claimRaceWorkers is how many goroutines compete for each single use claim.
const claimRaceWorkers = 24

// raceWinners runs fn from n goroutines released at the same moment and returns how many reported
// a win. A fn error other than the expected loss must be reported by fn itself through t.
func raceWinners(n int, fn func() bool) int {
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

// RunClaimRaces fires claimRaceWorkers parallel requests at every single use claim a storage
// backend owns and requires exactly one winner: magic links, password reset tokens, authorization
// codes, refresh token rotation, recovery codes, TOTP steps and account creation. Capabilities the
// store does not implement are skipped. A store that lets two callers win has a double spend.
func RunClaimRaces(t *testing.T, store any) {
	t.Helper()
	ctx := context.Background()

	t.Run("ClaimRaces", func(t *testing.T) {
		if s, ok := store.(theauth.MagicLinkStorage); ok {
			t.Run("MagicLink", func(t *testing.T) {
				hash := sha256Hash([]byte("race-ml-" + newID().String()))
				err := s.CreateMagicLink(ctx, theauth.MagicLink{
					ID: newID(), Email: "race-ml@storagetest.example", TokenHash: hash,
					CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
				})
				if err != nil {
					t.Fatalf("CreateMagicLink: %v", err)
				}
				wins := raceWinners(claimRaceWorkers, func() bool {
					_, err := s.ConsumeMagicLink(ctx, hash)
					if err != nil && !errors.Is(err, storage.ErrNotFound) {
						t.Errorf("ConsumeMagicLink: %v", err)
					}
					return err == nil
				})
				if wins != 1 {
					t.Fatalf("DOUBLE SPEND: %d winners consuming one magic link, want 1", wins)
				}
			})
		}

		if s, ok := store.(theauth.PasswordStorage); ok {
			t.Run("PasswordReset", func(t *testing.T) {
				uid := ensureUser(t, store, "race-reset")
				hash := sha256Hash([]byte("race-reset-" + newID().String()))
				err := s.CreatePasswordResetToken(ctx, theauth.PasswordResetToken{
					ID: newID(), UserID: uid, TokenHash: hash,
					CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
				})
				if err != nil {
					t.Fatalf("CreatePasswordResetToken: %v", err)
				}
				wins := raceWinners(claimRaceWorkers, func() bool {
					_, err := s.ConsumePasswordResetToken(ctx, hash)
					if err != nil && !errors.Is(err, storage.ErrNotFound) {
						t.Errorf("ConsumePasswordResetToken: %v", err)
					}
					return err == nil
				})
				if wins != 1 {
					t.Fatalf("DOUBLE SPEND: %d winners consuming one password reset token, want 1", wins)
				}
			})
		}

		if s, ok := store.(theauth.OAuthServerStorage); ok {
			t.Run("AuthorizationCode", func(t *testing.T) {
				uid := ensureUser(t, store, "race-code")
				clientID := "st-race-" + newID().String()
				ensureOAuthClient(t, s, clientID)
				code := "race-code-" + newID().String()
				err := s.InsertAuthorizationCode(ctx, theauth.AuthorizationCode{
					Code: code, ClientID: clientID, UserID: uid, Scope: []string{"openid"},
					ExpiresAt: time.Now().Add(time.Minute), CreatedAt: time.Now(),
				})
				if err != nil {
					t.Fatalf("InsertAuthorizationCode: %v", err)
				}
				wins := raceWinners(claimRaceWorkers, func() bool {
					_, err := s.ConsumeAuthorizationCode(ctx, code)
					if err != nil && !errors.Is(err, storage.ErrNotFound) {
						t.Errorf("ConsumeAuthorizationCode: %v", err)
					}
					return err == nil
				})
				if wins != 1 {
					t.Fatalf("DOUBLE SPEND: %d winners consuming one authorization code, want 1", wins)
				}
			})

			t.Run("RefreshRotation", func(t *testing.T) {
				uid := ensureUser(t, store, "race-refresh")
				clientID := "st-race-" + newID().String()
				ensureOAuthClient(t, s, clientID)
				hash := sha256Hash([]byte("race-refresh-" + newID().String()))
				err := s.InsertRefreshToken(ctx, theauth.RefreshToken{
					ID: newID(), Hash: hash, ClientID: clientID, UserID: &uid,
					FamilyID: newID(), Scope: []string{"openid"},
					ExpiresAt: time.Now().Add(time.Hour), IssuedAt: time.Now(),
				})
				if err != nil {
					t.Fatalf("InsertRefreshToken: %v", err)
				}
				wins := raceWinners(claimRaceWorkers, func() bool {
					err := s.RevokeRefreshToken(ctx, hash, "rotated")
					if err != nil && !errors.Is(err, storage.ErrNotFound) {
						t.Errorf("RevokeRefreshToken: %v", err)
					}
					return err == nil
				})
				if wins != 1 {
					t.Fatalf("DOUBLE SPEND: %d winners rotating one refresh token, want 1", wins)
				}
			})
		}

		if s, ok := store.(theauth.TOTPStorage); ok {
			t.Run("RecoveryCode", func(t *testing.T) {
				uid := ensureUser(t, store, "race-recovery")
				const plain = "race-recovery-code"
				h, err := crypto.HashRecoveryCode(plain)
				if err != nil {
					t.Fatalf("HashRecoveryCode: %v", err)
				}
				err = s.InsertRecoveryCodes(ctx, []theauth.RecoveryCode{
					{ID: newID(), UserID: uid, CodeHash: h, CreatedAt: time.Now()},
				})
				if err != nil {
					t.Fatalf("InsertRecoveryCodes: %v", err)
				}
				wins := raceWinners(claimRaceWorkers, func() bool {
					err := s.ConsumeRecoveryCode(ctx, uid, plain, time.Now())
					if err != nil && !errors.Is(err, storage.ErrNotFound) {
						t.Errorf("ConsumeRecoveryCode: %v", err)
					}
					return err == nil
				})
				if wins != 1 {
					t.Fatalf("DOUBLE SPEND: %d winners consuming one recovery code, want 1", wins)
				}
			})
		}

		if s, ok := store.(theauth.TOTPReplayStorage); ok {
			t.Run("TOTPStep", func(t *testing.T) {
				uid := ensureUser(t, store, "race-step")
				wins := raceWinners(claimRaceWorkers, func() bool {
					ok, err := s.AdvanceTOTPStep(ctx, uid, 7000)
					if err != nil {
						t.Errorf("AdvanceTOTPStep: %v", err)
					}
					return ok
				})
				if wins != 1 {
					t.Fatalf("DOUBLE SPEND: %d winners advancing one TOTP step, want 1", wins)
				}
			})
		}

		if s, ok := store.(theauth.APITokenStorage); ok {
			t.Run("APITokenRevoke", func(t *testing.T) {
				owner := ensureUser(t, store, "race-apitoken")
				now := time.Now().UTC().Truncate(time.Second)
				const n = 6
				for i := 0; i < n; i++ {
					tok := newTestToken(owner, theauth.OwnerKindUser, "race-"+newID().String(), now)
					if _, err := s.InsertAPIToken(ctx, tok); err != nil {
						t.Fatalf("InsertAPIToken: %v", err)
					}
				}
				var changed atomic.Int32
				raceWinners(claimRaceWorkers, func() bool {
					c, err := s.RevokeAPITokensByOwner(ctx, owner, time.Now())
					if err != nil {
						t.Errorf("RevokeAPITokensByOwner: %v", err)
					}
					changed.Add(int32(c))
					return false
				})
				if int(changed.Load()) != n {
					t.Fatalf("parallel owner revokes changed %d tokens in total, want exactly %d", changed.Load(), n)
				}
			})
		}

		if s, ok := store.(theauth.UserStorage); ok {
			t.Run("CreateUserSameEmail", func(t *testing.T) {
				email := "race-user-" + newID().String() + "@storagetest.example"
				wins := raceWinners(claimRaceWorkers, func() bool {
					_, err := s.CreateUser(ctx, theauth.User{ID: newID(), Email: email, CreatedAt: time.Now()})
					return err == nil
				})
				if wins != 1 {
					t.Fatalf("%d concurrent CreateUser calls with one email succeeded, want 1", wins)
				}
			})
		}
	})
}
