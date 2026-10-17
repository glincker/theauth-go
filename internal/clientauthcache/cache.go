// Package clientauthcache caches successful client_secret verifications (Argon2id), so hot
// endpoints do not pay the Argon2 cost on every request. The key is the client_id and the value
// binds the verified snapshot to the sha256 of the presented secret. Entries expire after a TTL,
// failures are never cached, and the cache is a bounded LRU. Invalidate must run on every secret
// rotation or deletion, and the plaintext secret is never stored.
package clientauthcache

import (
	"container/list"
	"crypto/sha256"
	"crypto/subtle"
	"sync"
	"time"
)

// DefaultMaxEntries bounds the cache so probing many synthetic client_ids cannot exhaust memory
// (about 1 MiB at the default).
const DefaultMaxEntries = 1024

// DefaultTTL bounds how long a verified entry stays usable. It stays within the introspection cache
// horizon, so a revoked secret does not linger.
const DefaultTTL = 5 * time.Minute

// entry is one cached verification. Only the sha256 digest of the presented secret is kept.
type entry[V any] struct {
	clientID     string
	secretDigest [sha256.Size]byte
	value        V
	expiresAt    time.Time
	elem         *list.Element // pointer back into the LRU list for O(1) move-to-front
}

// Cache is a bounded LRU keyed by client_id holding the verified client snapshot and the sha256 of
// the secret that authorized it. Every public method holds the mutex for its whole critical
// section, so operations stay O(1).
type Cache[V any] struct {
	mu         sync.Mutex
	maxEntries int
	ttl        time.Duration
	now        func() time.Time

	byID  map[string]*entry[V]
	order *list.List // front = most recently used
}

// New returns a cache. Non-positive limits fall back to DefaultMaxEntries and DefaultTTL.
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

// Get returns the cached value only when the entry exists, has not expired, and the presented
// secret's sha256 matches. A hit moves the entry to the LRU front. On a miss the caller must run
// the slow Argon2 verify.
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
		// A different secret for the same client_id is never served from cache. The slow verifier
		// decides, which also hides whether an entry exists.
		return zero, false
	}
	c.order.MoveToFront(e.elem)
	return e.value, true
}

// Put inserts or replaces the entry after a successful Argon2 verify of the same (clientID, secret)
// pair. It evicts the LRU entry at capacity.
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

// Invalidate drops the entry for clientID. Any path that rotates or revokes client_secret_hash must
// call it. Safe on a missing key.
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
