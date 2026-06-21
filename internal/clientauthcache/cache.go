// Package clientauthcache caches the result of an OAuth client_secret
// verification (Argon2id PHC compare) so that hot endpoints (introspect,
// token, revoke) do not pay the ~27ms Argon2 cost on every request.
//
// Contract:
//   - The cache key is the client_id; the cache VALUE binds the verified
//     client snapshot to the sha256 of the presented secret. A cache hit
//     therefore requires both the client_id and the same presented secret
//     bytes that produced the original Argon2 verify.
//   - Entries expire after a fixed TTL (default 5 minutes), bounding the
//     window during which a revoked-but-cached entry can authenticate.
//   - The cache is bounded (default 1024 entries) via simple LRU eviction so
//     a high cardinality of client_ids (or a credential-stuffing storm
//     hitting many client_id values) cannot grow memory without bound.
//   - Only successful verifications are cached. Failures are never cached so
//     an attacker cannot poison the cache to lock out a legitimate client.
//   - Invalidate(clientID) MUST be called by any code that mutates the
//     stored client_secret_hash. The contract is documented at the call
//     sites: UpdateOAuthClient (used by agent secret rotation) and
//     DeleteOAuthClient (used by failed agent creation cleanup).
//   - The cached entry is compared to the presented secret using a sha256
//     constant-time compare. The plaintext secret is never stored; only its
//     32-byte digest.
package clientauthcache

import (
	"container/list"
	"crypto/sha256"
	"crypto/subtle"
	"sync"
	"time"
)

// DefaultMaxEntries bounds the cache to a reasonable upper limit so an
// attacker probing many synthetic client_ids cannot exhaust process memory.
// At roughly 200 bytes per entry plus the OAuthClient pointee, 1024 entries
// is well under 1 MiB.
const DefaultMaxEntries = 1024

// DefaultTTL bounds how long a verified entry remains usable. Five minutes
// keeps the hot-path benefit (a typical resource server introspects every
// request inside this window) while ensuring a revoked secret never lingers
// past the documented introspection-cache horizon.
const DefaultTTL = 5 * time.Minute

// entry is one cached verification. The presented secret is never stored;
// only its sha256 digest is kept for constant-time comparison on subsequent
// lookups with the same client_id.
type entry[V any] struct {
	clientID     string
	secretDigest [sha256.Size]byte
	value        V
	expiresAt    time.Time
	elem         *list.Element // pointer back into the LRU list for O(1) move-to-front
}

// Cache is a bounded LRU keyed by client_id holding the verified client
// snapshot plus the sha256 of the presented secret that authorized the
// entry.
//
// Concurrency: every public method holds the cache's mutex for the duration
// of its critical section. Operations are O(1) under normal load. The
// underlying list.List plus map[string]*entry pattern is the same shape used
// by the standard library net/http transport.
type Cache[V any] struct {
	mu         sync.Mutex
	maxEntries int
	ttl        time.Duration
	now        func() time.Time

	byID  map[string]*entry[V]
	order *list.List // front = most recently used
}

// New returns a fresh cache. maxEntries less than or equal to 0 falls back
// to DefaultMaxEntries; ttl less than or equal to 0 falls back to
// DefaultTTL.
func New[V any](maxEntries int, ttl time.Duration) *Cache[V] {
	if maxEntries <= 0 {
		maxEntries = DefaultMaxEntries
	}
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	return &Cache[V]{
		maxEntries: maxEntries,
		ttl:        ttl,
		now:        time.Now,
		byID:       make(map[string]*entry[V], maxEntries),
		order:      list.New(),
	}
}

// Get returns the cached value for clientID if and only if (a) an entry
// exists, (b) it has not expired, and (c) the presented secret's sha256
// matches the digest stored on the entry. On a hit the entry is moved to
// the LRU front. On a miss (including digest mismatch or expiry), the
// caller MUST fall back to the slow Argon2 verify path; this method makes
// no statement about the validity of the supplied credential beyond the
// strict bytes-equality check.
func (c *Cache[V]) Get(clientID, secret string) (V, bool) {
	var zero V
	if c == nil || clientID == "" {
		return zero, false
	}
	digest := sha256.Sum256([]byte(secret))
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.byID[clientID]
	if !ok {
		return zero, false
	}
	if !c.now().Before(e.expiresAt) {
		// Expired: evict so the next miss does not have to expire again.
		c.removeLocked(e)
		return zero, false
	}
	if subtle.ConstantTimeCompare(e.secretDigest[:], digest[:]) != 1 {
		// Same client_id, different presented secret. Do NOT cache this
		// path; let the slow verifier decide. Returning false also avoids
		// leaking timing about whether the cached entry exists.
		return zero, false
	}
	c.order.MoveToFront(e.elem)
	return e.value, true
}

// Put inserts or replaces the entry for clientID. Always called after a
// successful Argon2 verify on the same (clientID, secret) pair. If an entry
// already exists it is replaced (the verified value is presumed fresher);
// the LRU position is moved to the front. If the cache is at capacity the
// least-recently-used entry is evicted.
func (c *Cache[V]) Put(clientID, secret string, value V) {
	if c == nil || clientID == "" {
		return
	}
	digest := sha256.Sum256([]byte(secret))
	c.mu.Lock()
	defer c.mu.Unlock()
	if existing, ok := c.byID[clientID]; ok {
		existing.secretDigest = digest
		existing.value = value
		existing.expiresAt = c.now().Add(c.ttl)
		c.order.MoveToFront(existing.elem)
		return
	}
	e := &entry[V]{
		clientID:     clientID,
		secretDigest: digest,
		value:        value,
		expiresAt:    c.now().Add(c.ttl),
	}
	e.elem = c.order.PushFront(e)
	c.byID[clientID] = e
	for c.order.Len() > c.maxEntries {
		oldest := c.order.Back()
		if oldest == nil {
			break
		}
		c.removeLocked(oldest.Value.(*entry[V]))
	}
}

// Invalidate drops the entry for clientID. MUST be called by any path that
// rotates or revokes the stored client_secret_hash (UpdateOAuthClient,
// DeleteOAuthClient). Safe on a missing key.
func (c *Cache[V]) Invalidate(clientID string) {
	if c == nil || clientID == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.byID[clientID]; ok {
		c.removeLocked(e)
	}
}

// Len returns the current entry count. Test-only helper.
func (c *Cache[V]) Len() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.order.Len()
}

func (c *Cache[V]) removeLocked(e *entry[V]) {
	c.order.Remove(e.elem)
	delete(c.byID, e.clientID)
}
