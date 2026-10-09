package password

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/glincker/theauth-go/v2/crypto"
	"github.com/glincker/theauth-go/v2/internal/models"
)

// VerifyCredential checks plain against a stored hash. A legacy (bcrypt or PBKDF2) hash with
// allowLegacy off is a plain mismatch, not an error. newHash is non-empty when
// a legacy hash matched and should be persisted; a rehash failure is logged and
// the match still stands.
func VerifyCredential(plain, stored string, allowLegacy bool) (ok bool, newHash string, err error) {
	if crypto.IsLegacyHash(stored) && !allowLegacy {
		return false, "", nil
	}
	ok, newHash, err = crypto.VerifyPasswordWithLegacyFallback(plain, stored, allowLegacy)
	if ok && err != nil {
		slog.Error("theauth: legacy password rehash failed", "err", err.Error())
		return true, "", nil
	}
	return ok, newHash, err
}

// UpgradeHash persists a rehashed password and reports whether it was stored; a storage failure is logged, never returned.
func UpgradeHash(ctx context.Context, set func(context.Context, models.ULID, string) error, userID models.ULID, newHash string) bool {
	if err := set(ctx, userID, newHash); err != nil {
		slog.Error("theauth: persist upgraded password hash failed", "user_id", userID.String(), "err", err.Error())
		return false
	}
	return true
}

// UpgradeAndNotify persists newHash, then invokes cb (if set) on its own goroutine.
func UpgradeAndNotify(ctx context.Context, set func(context.Context, models.ULID, string) error, cb func(userID, newHash string), userID models.ULID, newHash string) {
	if !UpgradeHash(ctx, set, userID, newHash) || cb == nil {
		return
	}
	id := userID.String()
	go func() {
		defer func() {
			if r := recover(); r != nil {
				slog.Error("theauth: OnLegacyHashAccepted callback panicked", "user_id", id, "panic", fmt.Sprint(r))
			}
		}()
		cb(id, newHash)
	}()
}
