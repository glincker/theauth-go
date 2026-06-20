package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters. OWASP 2026 baseline for argon2id:
//
//	memory  = 64 MiB
//	time    = 3 iterations
//	threads = 4
//	salt    = 16 bytes
//	key     = 32 bytes
//
// These constants are deliberately not configurable per-hash — the PHC string
// embeds the params used at hash time, so VerifyPassword stays correct even
// if we tune the defaults in a future release.
const (
	argonMemoryKiB = 64 * 1024
	argonTime      = 3
	argonThreads   = 4
	argonSaltLen   = 16
	argonKeyLen    = 32
)

// ErrInvalidPasswordHash is returned by VerifyPassword when the stored PHC
// string cannot be parsed. Callers should treat this as a server-side fault,
// not a credential mismatch.
var ErrInvalidPasswordHash = errors.New("crypto: invalid password hash")

// HashPassword returns an argon2id PHC-formatted hash of the plain password.
// Format:
//
//	$argon2id$v=19$m=<KiB>,t=<iters>,p=<threads>$<base64(salt)>$<base64(hash)>
//
// Salt is freshly random per call — two hashes of the same password differ.
func HashPassword(plain string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(plain), salt, argonTime, argonMemoryKiB, argonThreads, argonKeyLen)
	enc := base64.RawStdEncoding.EncodeToString
	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemoryKiB, argonTime, argonThreads, enc(salt), enc(key),
	), nil
}

// VerifyPassword parses the PHC string and constant-time-compares the supplied
// plain password against it. Returns (true, nil) on match, (false, nil) on
// mismatch, and (false, ErrInvalidPasswordHash) on a malformed hash.
func VerifyPassword(plain, phc string) (bool, error) {
	parts := strings.Split(phc, "$")
	// "$argon2id$v=19$m=...$salt$hash" -> ["", "argon2id", "v=19", "m=...,t=...,p=...", "salt", "hash"]
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return false, ErrInvalidPasswordHash
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false, ErrInvalidPasswordHash
	}
	var memory uint32
	var time uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads); err != nil {
		return false, ErrInvalidPasswordHash
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, ErrInvalidPasswordHash
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, ErrInvalidPasswordHash
	}
	got := argon2.IDKey([]byte(plain), salt, time, memory, threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}
