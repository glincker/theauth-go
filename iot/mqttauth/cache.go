package mqttauth

import (
	"hash/maphash"
	"sync"
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

func (c *cache) putDevice(d *Device) {
	if !c.enabled() {
		return
	}
	s := c.shard(d.ID)
	exp := c.now().Add(c.ttl)
	s.mu.Lock()
	defer s.mu.Unlock()
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

func (c *cache) putDecision(id, key string, d Decision) {
	if !c.enabled() {
		return
	}
	s := c.shard(id)
	exp := c.now().Add(c.ttl)
	s.mu.Lock()
	defer s.mu.Unlock()
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
		s.reset()
		s.mu.Unlock()
	}
}
