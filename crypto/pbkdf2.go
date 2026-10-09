package crypto

import (
	"crypto/pbkdf2"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"hash"
	"strconv"
	"strings"
)

// Legacy PBKDF2 hashes use the passlib-style form
//
//	$pbkdf2-sha256$<iterations>$<std base64 salt>$<std base64 key>
//
// (and pbkdf2-sha512). It is what Keycloak's default password policy stores,
// converted from its credential JSON by theauth-migrate. Like bcrypt, it is
// accepted only while PasswordPolicy.AllowLegacyBcrypt is on, and is replaced
// with Argon2id on the first successful login.

const (
	pbkdf2SHA256Prefix = "$pbkdf2-sha256$"
	pbkdf2SHA512Prefix = "$pbkdf2-sha512$"
	// maxPBKDF2Iterations bounds the work one stored hash can demand, so a
	// corrupt or hostile import cannot pin a CPU on a single login.
	maxPBKDF2Iterations = 5_000_000
)

// IsPBKDF2Hash reports whether hash is a legacy PBKDF2 string.
func IsPBKDF2Hash(hash string) bool {
	return strings.HasPrefix(hash, pbkdf2SHA256Prefix) || strings.HasPrefix(hash, pbkdf2SHA512Prefix)
}

// IsLegacyHash reports whether hash is any non-Argon2id format theauth can
// verify during a migration window (bcrypt or PBKDF2).
func IsLegacyHash(hash string) bool { return IsBcryptHash(hash) || IsPBKDF2Hash(hash) }

// FormatPBKDF2Hash builds the stored string from raw salt and key bytes.
func FormatPBKDF2Hash(algo string, iterations int, salt, key []byte) string {
	return fmt.Sprintf("$%s$%d$%s$%s", algo, iterations,
		base64.StdEncoding.EncodeToString(salt), base64.StdEncoding.EncodeToString(key))
}

// VerifyLegacyPBKDF2 checks plain against a legacy PBKDF2 hash. A mismatch is
// (false, nil); only a malformed hash returns an error.
func VerifyLegacyPBKDF2(plain, stored string) (bool, error) {
	parts := strings.Split(stored, "$")
	if len(parts) != 5 || parts[0] != "" {
		return false, ErrInvalidPasswordHash
	}
	var h func() hash.Hash
	switch parts[1] {
	case "pbkdf2-sha256":
		h = sha256.New
	case "pbkdf2-sha512":
		h = sha512.New
	default:
		return false, ErrInvalidPasswordHash
	}
	iterations, err := strconv.Atoi(parts[2])
	if err != nil || iterations < 1 || iterations > maxPBKDF2Iterations {
		return false, ErrInvalidPasswordHash
	}
	salt, err := base64.StdEncoding.DecodeString(parts[3])
	if err != nil {
		return false, ErrInvalidPasswordHash
	}
	want, err := base64.StdEncoding.DecodeString(parts[4])
	if err != nil || len(want) == 0 {
		return false, ErrInvalidPasswordHash
	}
	got, err := pbkdf2.Key(h, plain, salt, iterations, len(want))
	if err != nil {
		return false, ErrInvalidPasswordHash
	}
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}
