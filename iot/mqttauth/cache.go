package mqttauth

import (
	"hash/maphash"
	"sync"
	"sync/atomic"
	"time"
)

type deviceEntry struct {
	dev *Device
	exp time.Time
}

type decisionEntry struct {
	dec Decision
	exp time.Time
}

// maxShards is the number of independently locked partitions of a large cache. A device and all
// of its decisions live in one shard, so a purge touches one lock.
const maxShards = 16

// shardMinEntries is the smallest per shard capacity worth splitting for. A cache limited to
// fewer entries than shards times this value uses one shard, which keeps its eviction exact.
const shardMinEntries = 8

type shard struct {
	mu        sync.RWMutex
	devices   map[string]deviceEntry
	decisions map[string]map[string]decisionEntry
	size      int // decision entries
	max       int // per shard limit, zero means unlimited
	// epoch counts the purges of this shard. A reader takes a token (the epoch) before it reads the
	// store and passes it to putDevice or putDecision, which drop the entry when a purge ran in
	// between. Bumped under mu, read without it.
	epoch atomic.Uint64
}

// cache holds recently loaded devices and recent authorization decisions, both per device so a
// purge drops everything about one device. Revocation latency is bounded by ttl, or zero when the
// purge endpoint is called. Lookups take a shared lock, so concurrent publishes for different
// devices (and for one device) do not queue behind each other.
type cache struct {
	ttl    time.Duration
	now    func() time.Time
	seed   maphash.Seed
	shards []*shard
}

func newCache(ttl time.Duration, max int, now func() time.Time) *cache {
	n := maxShards
	if max > 0 && max < maxShards*shardMinEntries {
		n = 1
	}
	c := &cache{ttl: ttl, now: now, seed: maphash.MakeSeed(), shards: make([]*shard, n)}
	per := 0
	if max > 0 {
		per = (max + n - 1) / n
	}
	for i := range c.shards {
		c.shards[i] = &shard{devices: map[string]deviceEntry{}, decisions: map[string]map[string]decisionEntry{}, max: per}
	}
	return c
}

// epochSnap holds the epoch of every shard. /authn takes one before it resolves a device by
// certificate, subject or token, when the device ID (and so the shard) is not known yet.
type epochSnap [maxShards]uint64

// token returns the purge epoch for a device. Take it before reading the store, and pass it to
// putDevice or putDecision so a load that raced a purge cannot be cached.
func (c *cache) token(id string) uint64 { return c.shard(id).epoch.Load() }

func (c *cache) snapshot() (e epochSnap) {
	for i, s := range c.shards {
		e[i] = s.epoch.Load()
	}
	return e
}

// tokenFrom picks the token for a device out of a snapshot.
func (c *cache) tokenFrom(e epochSnap, id string) uint64 {
	if len(c.shards) == 1 {
		return e[0]
	}
	return e[maphash.String(c.seed, id)%uint64(len(c.shards))]
}

func (c *cache) enabled() bool { return c.ttl > 0 }

func (c *cache) shard(id string) *shard {
	if len(c.shards) == 1 {
		return c.shards[0]
	}
	return c.shards[maphash.String(c.seed, id)%uint64(len(c.shards))]
}

func (c *cache) device(id string) (*Device, bool) {
	if !c.enabled() {
		return nil, false
	}
	s := c.shard(id)
	now := c.now()
	s.mu.RLock()
	e, ok := s.devices[id]
	s.mu.RUnlock()
	if !ok {
		return nil, false
	}
	if now.Before(e.exp) {
		return e.dev, true
	}
	// Expired: drop it, unless another goroutine already replaced it with a fresh entry.
	s.mu.Lock()
	if cur, ok := s.devices[id]; ok && !now.Before(cur.exp) {
		delete(s.devices, id)
	}
	s.mu.Unlock()
	return nil, false
}

// putDevice caches d unless a purge of its shard ran since tok was taken.
func (c *cache) putDevice(d *Device, tok uint64) {
	if !c.enabled() {
		return
	}
	s := c.shard(d.ID)
	exp := c.now().Add(c.ttl)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.epoch.Load() != tok {
		return
	}
	s.makeRoom()
	s.devices[d.ID] = deviceEntry{dev: d, exp: exp}
}

func (c *cache) decision(id, key string) (Decision, bool) {
	if !c.enabled() {
		return Decision{}, false
	}
	s := c.shard(id)
	now := c.now()
	s.mu.RLock()
	e, ok := s.decisions[id][key]
	s.mu.RUnlock()
	if !ok || !now.Before(e.exp) {
		return Decision{}, false
	}
	return e.dec, true
}

// putDecision caches d unless a purge of the device's shard ran since tok was taken.
func (c *cache) putDecision(id, key string, d Decision, tok uint64) {
	if !c.enabled() {
		return
	}
	s := c.shard(id)
	exp := c.now().Add(c.ttl)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.epoch.Load() != tok {
		return
	}
	s.makeRoom()
	m := s.decisions[id]
	if m == nil {
		m = map[string]decisionEntry{}
		s.decisions[id] = m
	}
	if _, ok := m[key]; !ok {
		s.size++
	}
	m[key] = decisionEntry{dec: d, exp: exp}
}

// makeRoom drops everything in the shard when it is full. Entries live only a few seconds, so a
// flush costs a few store reads and keeps the structure simple. The caller holds the write lock.
func (s *shard) makeRoom() {
	if s.max > 0 && s.size+len(s.devices) >= s.max {
		s.reset()
	}
}

func (s *shard) reset() {
	s.devices = map[string]deviceEntry{}
	s.decisions = map[string]map[string]decisionEntry{}
	s.size = 0
}

// purge forgets one device. It reports how many entries were dropped.
func (c *cache) purge(id string) int {
	s := c.shard(id)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.epoch.Add(1)
	n := len(s.decisions[id])
	s.size -= n
	delete(s.decisions, id)
	if _, ok := s.devices[id]; ok {
		delete(s.devices, id)
		n++
	}
	return n
}

func (c *cache) purgeAll() {
	for _, s := range c.shards {
		s.mu.Lock()
		s.epoch.Add(1)
		s.reset()
		s.mu.Unlock()
	}
}
