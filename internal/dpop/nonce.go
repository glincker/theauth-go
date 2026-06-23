package dpop

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// nonce.go: server-issued DPoP-Nonce values per RFC 9449 section 8.
//
// A nonce is a short opaque string the AS / resource server hands to the
// client via the DPoP-Nonce response header. The client must echo it back
// in the nonce claim of the next DPoP proof. Nonces stop a proof captured
// at time T from being replayable beyond NonceTTL even when the client's
// private key remains uncompromised.
//
// Storage model: stateless. Each nonce is the base64url encoding of
// (issuedAtUnix || HMAC-SHA256(secret, issuedAtUnix)), keyed by a 32-byte
// HMAC secret generated at Service.New time. Verification recomputes the
// HMAC and rejects any nonce older than NonceTTL. No per-nonce server
// state means there is no growth pressure and no replication concern, at
// the cost of letting the same nonce be presented twice within the TTL
// (which is fine: jti-replay protection on the proof itself catches a
// duplicate use).

// nonceVersion prefixes every issued nonce so the wire format can rev
// without ambiguity. Version 1: 8-byte BE iat || 32-byte HMAC.
const nonceVersion byte = 1

// nonceLen is the byte length of an unencoded v1 nonce: 1 version byte +
// 8 iat bytes + 32 HMAC bytes.
const nonceLen = 1 + 8 + sha256.Size

// IssueNonce returns a fresh DPoP-Nonce. now defaults to time.Now().UTC()
// when zero. secret must be the per-service HMAC secret allocated by
// Service.New (32 random bytes).
func issueNonce(secret []byte, now time.Time) string {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	buf := make([]byte, nonceLen)
	buf[0] = nonceVersion
	binary.BigEndian.PutUint64(buf[1:9], uint64(now.Unix()))
	mac := hmac.New(sha256.New, secret)
	mac.Write(buf[:9])
	copy(buf[9:], mac.Sum(nil))
	return base64.RawURLEncoding.EncodeToString(buf)
}

// verifyNonce returns nil when nonce is well-formed, HMAC-valid under
// secret, and not older than ttl as of now.
func verifyNonce(secret []byte, nonce string, ttl time.Duration, now time.Time) error {
	if nonce == "" {
		return ErrNonceInvalid
	}
	raw, err := base64.RawURLEncoding.DecodeString(nonce)
	if err != nil {
		return fmt.Errorf("%w: decode: %v", ErrNonceInvalid, err)
	}
	if len(raw) != nonceLen || raw[0] != nonceVersion {
		return fmt.Errorf("%w: wrong shape", ErrNonceInvalid)
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(raw[:9])
	want := mac.Sum(nil)
	if !hmac.Equal(want, raw[9:]) {
		return fmt.Errorf("%w: hmac mismatch", ErrNonceInvalid)
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	iat := time.Unix(int64(binary.BigEndian.Uint64(raw[1:9])), 0)
	if now.Sub(iat) > ttl {
		return fmt.Errorf("%w: expired (age=%s, ttl=%s)", ErrNonceInvalid, now.Sub(iat), ttl)
	}
	// Reject nonces issued in the far future too (clock skew bound).
	if iat.Sub(now) > ttl {
		return fmt.Errorf("%w: iat in the future", ErrNonceInvalid)
	}
	return nil
}

// newNonceSecret returns 32 random bytes suitable for HMAC-SHA256.
func newNonceSecret() ([]byte, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("dpop: nonce secret: %w", err)
	}
	return b, nil
}

// errNonceSecretRequired is returned when the service has no secret
// configured; should be impossible in practice because Service.New seeds
// one, but Verify treats it as a configuration error.
var errNonceSecretRequired = errors.New("dpop: nonce secret not configured")
