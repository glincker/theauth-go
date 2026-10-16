package checkpoint

import (
	"context"
	"sort"
	"sync"
)

// Store keeps checkpoints.
type Store interface {
	// Put saves a checkpoint. Saving the same checkpoint twice is a no op.
	Put(ctx context.Context, c Checkpoint) error
	// Latest returns the checkpoint with the largest size (latest timestamp on a tie).
	Latest(ctx context.Context) (Checkpoint, bool, error)
	// BySize returns all checkpoints of exactly this size, oldest first.
	BySize(ctx context.Context, size int64) ([]Checkpoint, error)
	// List returns every checkpoint ordered by size then timestamp.
	List(ctx context.Context) ([]Checkpoint, error)
}

// MemoryStore is a Store that keeps everything in process memory.
type MemoryStore struct {
	mu    sync.Mutex
	items []Checkpoint
}

// NewMemoryStore returns an empty in memory store.
func NewMemoryStore() *MemoryStore { return &MemoryStore{} }

func sameCheckpoint(a, b Checkpoint) bool {
	return a.Size == b.Size && a.RootHash == b.RootHash && a.KeyID == b.KeyID && a.Timestamp == b.Timestamp &&
		sameBound(a.Since, b.Since) && sameBound(a.Until, b.Until) && a.Signature == b.Signature
}

func clone(c Checkpoint) Checkpoint {
	if c.Since != nil {
		v := *c.Since
		c.Since = &v
	}
	if c.Until != nil {
		v := *c.Until
		c.Until = &v
	}
	return c
}

// Put implements Store.
func (s *MemoryStore) Put(_ context.Context, c Checkpoint) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, it := range s.items {
		if sameCheckpoint(it, c) {
			return nil
		}
	}
	s.items = append(s.items, clone(c))
	sort.SliceStable(s.items, func(i, j int) bool {
		if s.items[i].Size != s.items[j].Size {
			return s.items[i].Size < s.items[j].Size
		}
		return s.items[i].Timestamp < s.items[j].Timestamp
	})
	return nil
}

// Latest implements Store.
func (s *MemoryStore) Latest(context.Context) (Checkpoint, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.items) == 0 {
		return Checkpoint{}, false, nil
	}
	return clone(s.items[len(s.items)-1]), true, nil
}

// BySize implements Store.
func (s *MemoryStore) BySize(_ context.Context, size int64) ([]Checkpoint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []Checkpoint{}
	for _, it := range s.items {
		if it.Size == size {
			out = append(out, clone(it))
		}
	}
	return out, nil
}

// List implements Store.
func (s *MemoryStore) List(context.Context) ([]Checkpoint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Checkpoint, len(s.items))
	for i, it := range s.items {
		out[i] = clone(it)
	}
	return out, nil
}
