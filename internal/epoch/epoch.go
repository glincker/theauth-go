// Package epoch guards read-through caches against a store that races an invalidation.
//
// A cache that does Load, then a slow lookup, then Store has a window: an Invalidate that runs
// between the lookup and the Store is undone when the Store lands, so a revoked subject or token
// stays cached until its TTL. A Set closes the window. The reader takes a Token before it reads the
// store and commits its entry with Commit, which drops the entry when an invalidation of the same
// key shard ran in between. Invalidate bumps the epoch and removes the entry under the same shard
// mutex that Commit takes, so a store either lands before the invalidation (and is removed by it)
// or sees the new epoch and is dropped.
//
// Keys hash into a fixed number of shards, so there is no global lock and no per key state. Two
// keys that share a shard can drop each other's in flight store, which only costs a cache miss.
// Reads of the cache itself never touch a Set.
package epoch

import (
	"sync"
	"sync/atomic"
)

const shardCount = 64

type shard struct {
	mu sync.Mutex
	n  atomic.Uint64
	_  [40]byte // keep neighbouring shards off one cache line
}

// Set is a group of sharded purge counters. The zero value is ready to use.
type Set struct {
	shards [shardCount]shard
}

func (s *Set) shard(key string) *shard {
	h := uint32(2166136261) // FNV-1a
	for i := 0; i < len(key); i++ {
		h ^= uint32(key[i])
		h *= 16777619
	}
	return &s.shards[h%shardCount]
}

// Token returns the epoch of key's shard. Take it before reading the store.
func (s *Set) Token(key string) uint64 { return s.shard(key).n.Load() }

// Commit runs store while holding key's shard mutex, unless an invalidation of the shard ran since
// tok was taken. It reports whether store ran.
func (s *Set) Commit(key string, tok uint64, store func()) bool {
	sh := s.shard(key)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	if sh.n.Load() != tok {
		return false
	}
	store()
	return true
}

// Invalidate bumps key's shard epoch and runs remove under the shard mutex. Call it after the
// underlying state change (the revoke or deactivation) has been written.
func (s *Set) Invalidate(key string, remove func()) {
	sh := s.shard(key)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	sh.n.Add(1)
	if remove != nil {
		remove()
	}
}

// InvalidateAll bumps every shard epoch, then runs removeAll. A store that began before the call is
// dropped. Use it for a purge that is not keyed.
func (s *Set) InvalidateAll(removeAll func()) {
	for i := range s.shards {
		sh := &s.shards[i]
		sh.mu.Lock()
		sh.n.Add(1)
		sh.mu.Unlock()
	}
	if removeAll != nil {
		removeAll()
	}
}
