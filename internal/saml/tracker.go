package saml

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/glincker/theauth-go/v2/kv"
)

// Key prefixes used by KVTracker. Only digests and the connection id are
// stored, never the SAML document.
const (
	authnKeyPrefix  = "saml:authn:"
	assertKeyPrefix = "saml:assert:"
)

// RequestTracker remembers the AuthnRequest ids this SP issued and the
// assertion ids it has accepted, so InResponseTo is enforced, every id is
// usable once, and replay protection holds across replicas when the
// implementation is shared.
type RequestTracker interface {
	// Issue records requestID for connectionID until now+ttl. relayState is
	// bound to the record (as a digest) so Consume can check it.
	Issue(ctx context.Context, connectionID, requestID, relayState string, ttl time.Duration) error

	// Consume atomically marks requestID used. It reports true only for the
	// first call, only when the id was issued for connectionID and has not
	// expired, and, when relayState is not empty, only when it matches the
	// relay state recorded at Issue. Of N concurrent callers at most one
	// gets true.
	Consume(ctx context.Context, connectionID, requestID, relayState string) (bool, error)

	// SeenAssertion records assertionID for ttl and reports whether it was
	// already recorded. Of N concurrent callers with the same id exactly one
	// gets false.
	SeenAssertion(ctx context.Context, connectionID, assertionID string, ttl time.Duration) (bool, error)
}

type memEntry struct {
	connectionID string
	relayDigest  string
	deadline     time.Time
}

// MemoryTracker is the default in-process RequestTracker. It keeps today's
// single process behavior: with more than one replica a response that lands
// on a replica that did not issue the request is rejected, and replay
// protection does not span replicas. Use NewKVTracker with a shared kv.Cache
// for multi replica deployments.
type MemoryTracker struct {
	mu        sync.Mutex
	requests  map[string]memEntry
	assertion map[string]time.Time
	now       func() time.Time
}

// NewMemoryTracker returns an empty in-process tracker.
func NewMemoryTracker() *MemoryTracker {
	return &MemoryTracker{
		requests:  map[string]memEntry{},
		assertion: map[string]time.Time{},
		now:       time.Now,
	}
}

// Issue implements RequestTracker.
func (m *MemoryTracker) Issue(_ context.Context, connectionID, requestID, relayState string, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests[requestID] = memEntry{
		connectionID: connectionID,
		relayDigest:  digest(relayState),
		deadline:     m.now().Add(ttl),
	}
	return nil
}

// Consume implements RequestTracker.
func (m *MemoryTracker) Consume(_ context.Context, connectionID, requestID, relayState string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.requests[requestID]
	if !ok {
		return false, nil
	}
	if m.now().After(e.deadline) {
		delete(m.requests, requestID)
		return false, nil
	}
	if e.connectionID != connectionID || (relayState != "" && e.relayDigest != digest(relayState)) {
		// A mismatch must not burn the legitimate request.
		return false, nil
	}
	delete(m.requests, requestID)
	return true, nil
}

// SeenAssertion implements RequestTracker.
func (m *MemoryTracker) SeenAssertion(_ context.Context, connectionID, assertionID string, ttl time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := connectionID + "|" + assertionID
	now := m.now()
	if dl, ok := m.assertion[key]; ok && now.Before(dl) {
		return true, nil
	}
	m.assertion[key] = now.Add(ttl)
	return false, nil
}

// Sweep drops expired entries. The Service GC loop calls it every minute.
func (m *MemoryTracker) Sweep(now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, e := range m.requests {
		if now.After(e.deadline) {
			delete(m.requests, k)
		}
	}
	for k, dl := range m.assertion {
		if now.After(dl) {
			delete(m.assertion, k)
		}
	}
}

// KVTracker is a RequestTracker backed by a kv.Cache, so replicas that share
// the cache (Redis, SQL) agree on which requests are outstanding. Consume is
// made atomic with SetNX on a "used" marker: of N concurrent responses
// exactly one wins. Backend errors are returned, so callers fail closed.
type KVTracker struct {
	cache kv.Cache
	now   func() time.Time
}

// NewKVTracker returns a tracker over cache. It panics on a nil cache, which
// is a wiring bug.
func NewKVTracker(cache kv.Cache) *KVTracker {
	if cache == nil {
		panic("saml: NewKVTracker requires a non-nil kv.Cache")
	}
	return &KVTracker{cache: cache, now: time.Now}
}

func reqKey(requestID string) string  { return authnKeyPrefix + "req:" + digest(requestID) }
func usedKey(requestID string) string { return authnKeyPrefix + "used:" + digest(requestID) }

// record layout: connectionID + "\n" + relay digest. No raw document.
func encodeRecord(connectionID, relayState string) []byte {
	return []byte(connectionID + "\n" + digest(relayState))
}

func splitRecord(b []byte) (conn, relay string, ok bool) {
	for i, c := range b {
		if c == '\n' {
			return string(b[:i]), string(b[i+1:]), true
		}
	}
	return "", "", false
}

// Issue implements RequestTracker.
func (k *KVTracker) Issue(ctx context.Context, connectionID, requestID, relayState string, ttl time.Duration) error {
	if ttl <= 0 {
		return errors.New("saml: request ttl must be positive")
	}
	return k.cache.Set(ctx, reqKey(requestID), encodeRecord(connectionID, relayState), ttl)
}

// Consume implements RequestTracker.
func (k *KVTracker) Consume(ctx context.Context, connectionID, requestID, relayState string) (bool, error) {
	v, ok, err := k.cache.Get(ctx, reqKey(requestID))
	if err != nil || !ok {
		return false, err
	}
	conn, relay, ok := splitRecord(v)
	if !ok || conn != connectionID || (relayState != "" && relay != digest(relayState)) {
		return false, nil
	}
	// The used marker outlives the request record by the same bound, so a
	// replay after the record is deleted is still refused.
	won, err := k.cache.SetNX(ctx, usedKey(requestID), []byte{1}, markerTTL)
	if err != nil || !won {
		return false, err
	}
	if err := k.cache.Delete(ctx, reqKey(requestID)); err != nil {
		return true, nil // consumed; the record expires on its own TTL
	}
	return true, nil
}

// SeenAssertion implements RequestTracker.
func (k *KVTracker) SeenAssertion(ctx context.Context, connectionID, assertionID string, ttl time.Duration) (bool, error) {
	stored, err := k.cache.SetNX(ctx, assertKeyPrefix+digest(connectionID+"|"+assertionID), []byte{1}, ttl)
	if err != nil {
		return false, err
	}
	return !stored, nil
}

// markerTTL bounds the used marker. It must exceed any request TTL; one hour
// covers the 10 minute default with a wide margin.
const markerTTL = time.Hour

func digest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
