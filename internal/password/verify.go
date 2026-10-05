package password

import (
	"context"
	"log/slog"

	"github.com/glincker/theauth-go/v2/crypto"
	"github.com/glincker/theauth-go/v2/internal/models"
)

// VerifyCredential checks plain against a stored hash. A bcrypt hash with
// allowLegacy off is a plain mismatch, not an error. newHash is non-empty when
// a legacy hash matched and should be persisted; a rehash failure is logged and
// the match still stands.
func VerifyCredential(plain, stored string, allowLegacy bool) (ok bool, newHash string, err error) {
	if crypto.IsBcryptHash(stored) && !allowLegacy {
		return false, "", nil
	}
	ok, newHash, err = crypto.VerifyPasswordWithLegacyFallback(plain, stored, allowLegacy)
	if ok && err != nil {
		slog.Error("theauth: legacy password rehash failed", "err", err.Error())
		return true, "", nil
	}
	return ok, newHash, err
}

// UpgradeHash persists a rehashed password; a storage failure is logged, never returned.
func UpgradeHash(ctx context.Context, set func(context.Context, models.ULID, string) error, userID models.ULID, newHash string) {
	if err := set(ctx, userID, newHash); err != nil {
		slog.Error("theauth: persist upgraded password hash failed", "user_id", userID.String(), "err", err.Error())
	}
}
