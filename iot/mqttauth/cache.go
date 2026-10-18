package mqttauth

import (
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

// cache holds recently loaded devices and recent authorization decisions, both per device so a
// purge drops everything about one device. Revocation latency is bounded by ttl, or zero when the
// purge endpoint is called.
type cache struct {
	mu        sync.Mutex
	ttl       time.Duration
	max       int
	now       func() time.Time
	devices   map[string]deviceEntry
	decisions map[string]map[string]decisionEntry
	size      int
}

func newCache(ttl time.Duration, max int, now func() time.Time) *cache {
	return &cache{ttl: ttl, max: max, now: now, devices: map[string]deviceEntry{}, decisions: map[string]map[string]decisionEntry{}}
}

func (c *cache) enabled() bool { return c.ttl > 0 }

func (c *cache) device(id string) (*Device, bool) {
	if !c.enabled() {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.devices[id]
	if !ok || !c.now().Before(e.exp) {
		delete(c.devices, id)
		return nil, false
	}
	return e.dev, true
}

func (c *cache) putDevice(d *Device) {
	if !c.enabled() {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.makeRoom()
	c.devices[d.ID] = deviceEntry{dev: d, exp: c.now().Add(c.ttl)}
}

func (c *cache) decision(id, key string) (Decision, bool) {
	if !c.enabled() {
		return Decision{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.decisions[id][key]
	if !ok || !c.now().Before(e.exp) {
		return Decision{}, false
	}
	return e.dec, true
}

func (c *cache) putDecision(id, key string, d Decision) {
	if !c.enabled() {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.makeRoom()
	m := c.decisions[id]
	if m == nil {
		m = map[string]decisionEntry{}
		c.decisions[id] = m
	}
	if _, ok := m[key]; !ok {
		c.size++
	}
	m[key] = decisionEntry{dec: d, exp: c.now().Add(c.ttl)}
}

// makeRoom drops everything when the cache is full. Entries live only a few seconds, so a flush
// costs a few store reads and keeps the structure simple.
func (c *cache) makeRoom() {
	if c.max > 0 && c.size+len(c.devices) >= c.max {
		c.devices = map[string]deviceEntry{}
		c.decisions = map[string]map[string]decisionEntry{}
		c.size = 0
	}
}

// purge forgets one device. It reports how many entries were dropped.
func (c *cache) purge(id string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := len(c.decisions[id])
	c.size -= n
	delete(c.decisions, id)
	if _, ok := c.devices[id]; ok {
		delete(c.devices, id)
		n++
	}
	return n
}

func (c *cache) purgeAll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.devices = map[string]deviceEntry{}
	c.decisions = map[string]map[string]decisionEntry{}
	c.size = 0
}
