package crypto

import (
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// IsBcryptHash reports whether hash looks like a bcrypt PHC string.
// Bcrypt hashes start with "$2a$", "$2b$", or "$2x$".
func IsBcryptHash(hash string) bool {
	return strings.HasPrefix(hash, "$2a$") ||
		strings.HasPrefix(hash, "$2b$") ||
		strings.HasPrefix(hash, "$2x$")
}

// VerifyLegacyBcrypt checks plain against a bcrypt hash. It returns true
// when the password matches and false when it does not. An error is returned
// only for malformed hashes (e.g. wrong version byte), not for mismatches.
//
// This function is used during the Auth0 migration window when
// Config.PasswordPolicy.AllowLegacyBcrypt is true. Once all active users
// have logged in and had their hashes re-hashed with Argon2id, this path
// becomes unreachable and the config knob should be set back to false.
func VerifyLegacyBcrypt(plain, hash string) (bool, error) {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain))
	if err == nil {
		return true, nil
	}
	if err == bcrypt.ErrMismatchedHashAndPassword {
		return false, nil
	}
	return false, err
}

// VerifyPasswordWithLegacyFallback is a drop-in replacement for VerifyPassword
// that also accepts bcrypt hashes when allowLegacy is true. On a successful
// bcrypt match it calls onLegacyAccepted with the user ID and the NEW
// Argon2id hash so the caller can persist the upgrade asynchronously.
//
// Callers should schedule the hash upgrade via a goroutine or a job queue
// so the user-facing latency stays unchanged.
//
// Returns (matched bool, newHash string, err error). newHash is non-empty
// only when a bcrypt hash was accepted and re-hashed successfully.
func VerifyPasswordWithLegacyFallback(plain, storedHash string, allowLegacy bool) (matched bool, newArgon2Hash string, err error) {
	if IsBcryptHash(storedHash) {
		if !allowLegacy {
			// If legacy support is disabled, treat as invalid hash format.
			return false, "", ErrInvalidPasswordHash
		}
		ok, bcryptErr := VerifyLegacyBcrypt(plain, storedHash)
		if bcryptErr != nil {
			return false, "", bcryptErr
		}
		if !ok {
			return false, "", nil
		}
		// Re-hash with Argon2id for the upgrade.
		newHash, hashErr := HashPassword(plain)
		if hashErr != nil {
			// Still report the match even if re-hashing fails; the caller can
			// retry the upgrade later.
			return true, "", hashErr
		}
		return true, newHash, nil
	}

	// Standard Argon2id path.
	ok, verifyErr := VerifyPassword(plain, storedHash)
	return ok, "", verifyErr
}
