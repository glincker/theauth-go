package mcpresource

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"time"
)

// dpop_nonce.go: resource server provided DPoP nonces (RFC 9449 section 9)
// and the pluggable jti replay cache.
//
// Nonces are stateless. A nonce is the current time window number followed by
// an HMAC-SHA256 tag over it, so several instances that share the secret
// accept each other's nonces without sharing any storage. A nonce is valid in
// the window it was issued and the one after, so its lifetime is between one
// and two times the configured TTL.

// DPoPReplayCache remembers DPoP proof jti values so a proof cannot be used
// twice (RFC 9449 section 11.1). The default is an in-memory cache per
// Validator. Deployments with several instances behind one load balancer
// should supply a shared implementation (Redis SET NX with an expiry, or a
// database unique key).
type DPoPReplayCache interface {
	// Remember records jti until expiresAt and reports true when it was not
	// seen before. It must be atomic: of two concurrent calls with the same
	// jti exactly one returns true. An error or false rejects the proof.
	Remember(jti string, expiresAt time.Time) bool
}

type dpopNonces struct {
	secret []byte
	window time.Duration
}

func newDPoPNonces(secret []byte, ttl time.Duration) *dpopNonces {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	if len(secret) == 0 {
		secret = make([]byte, 32)
		// crypto/rand.Read does not return an error since Go 1.24; it
		// aborts the program if the system source fails.
		_, _ = rand.Read(secret)
	}
	return &dpopNonces{secret: append([]byte(nil), secret...), window: ttl}
}

func (n *dpopNonces) windowNumber(t time.Time) uint64 {
	return uint64(t.UnixNano() / int64(n.window)) //nolint:gosec // time after 1970, never negative in practice
}

func (n *dpopNonces) mac(win uint64) []byte {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], win)
	h := hmac.New(sha256.New, n.secret)
	h.Write([]byte("theauth-dpop-nonce"))
	h.Write(buf[:])
	return h.Sum(nil)[:16]
}

// issue returns the nonce for the window containing now.
func (n *dpopNonces) issue(now time.Time) string {
	win := n.windowNumber(now)
	out := make([]byte, 8, 24)
	binary.BigEndian.PutUint64(out, win)
	out = append(out, n.mac(win)...)
	return base64.RawURLEncoding.EncodeToString(out)
}

// valid reports whether nonce was issued in the current or previous window.
func (n *dpopNonces) valid(nonce string, now time.Time) bool {
	raw, err := base64.RawURLEncoding.DecodeString(nonce)
	if err != nil || len(raw) != 24 {
		return false
	}
	win := binary.BigEndian.Uint64(raw[:8])
	cur := n.windowNumber(now)
	if win != cur && win+1 != cur {
		return false
	}
	return hmac.Equal(raw[8:], n.mac(win))
}
