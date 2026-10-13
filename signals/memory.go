package signals

import (
	"context"
	"sort"
	"sync"
	"time"
)

// MemoryStore is an in-memory Store for tests and single-process setups.
type MemoryStore struct {
	mu       sync.Mutex
	streams  map[string]Stream
	subjects map[string]map[string][]byte
	queue    map[string]PendingSET
}

// NewMemoryStore returns an empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		streams:  map[string]Stream{},
		subjects: map[string]map[string][]byte{},
		queue:    map[string]PendingSET{},
	}
}

var _ Store = (*MemoryStore)(nil)

func (m *MemoryStore) CreateStream(_ context.Context, s Stream) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.streams[s.ID] = s
	return nil
}

func (m *MemoryStore) GetStream(_ context.Context, id string) (Stream, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.streams[id]
	if !ok {
		return Stream{}, ErrNotFound
	}
	return s, nil
}

func (m *MemoryStore) ListStreams(_ context.Context, receiverID string) ([]Stream, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Stream
	for _, s := range m.streams {
		if receiverID == "" || s.ReceiverID == receiverID {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (m *MemoryStore) UpdateStream(_ context.Context, s Stream) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.streams[s.ID]; !ok {
		return ErrNotFound
	}
	m.streams[s.ID] = s
	push := s.IsPush()
	for id, p := range m.queue {
		if p.StreamID == s.ID {
			p.Push = push
			m.queue[id] = p
		}
	}
	return nil
}

func (m *MemoryStore) DeleteStream(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.streams, id)
	delete(m.subjects, id)
	for qid, p := range m.queue {
		if p.StreamID == id {
			delete(m.queue, qid)
		}
	}
	return nil
}

func (m *MemoryStore) AddSubject(_ context.Context, streamID, key string, subject []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.subjects[streamID] == nil {
		m.subjects[streamID] = map[string][]byte{}
	}
	m.subjects[streamID][key] = append([]byte(nil), subject...)
	return nil
}

func (m *MemoryStore) RemoveSubject(_ context.Context, streamID, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.subjects[streamID], key)
	return nil
}

func (m *MemoryStore) HasSubject(_ context.Context, streamID, key string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.subjects[streamID][key]
	return ok, nil
}

func (m *MemoryStore) CountSubjects(_ context.Context, streamID string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.subjects[streamID]), nil
}

func (m *MemoryStore) Enqueue(_ context.Context, p PendingSET) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.queue[p.ID] = p
	return nil
}

func (m *MemoryStore) sorted(match func(PendingSET) bool, limit int) []PendingSET {
	var out []PendingSET
	for _, p := range m.queue {
		if match(p) {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func (m *MemoryStore) DuePush(_ context.Context, now time.Time, limit int) ([]PendingSET, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sorted(func(p PendingSET) bool { return p.Push && !p.NextAt.After(now) }, limit), nil
}

func (m *MemoryStore) Pending(_ context.Context, streamID string, limit int) ([]PendingSET, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sorted(func(p PendingSET) bool { return p.StreamID == streamID }, limit), nil
}

func (m *MemoryStore) CountPending(_ context.Context, streamID string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sorted(func(p PendingSET) bool { return p.StreamID == streamID }, 0)), nil
}

func (m *MemoryStore) MarkAttempt(_ context.Context, id string, attempts int, next time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if p, ok := m.queue[id]; ok {
		p.Attempts, p.NextAt = attempts, next
		m.queue[id] = p
	}
	return nil
}

func (m *MemoryStore) Ack(_ context.Context, streamID string, jtis []string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	want := make(map[string]bool, len(jtis))
	for _, j := range jtis {
		want[j] = true
	}
	n := 0
	for id, p := range m.queue {
		if p.StreamID == streamID && want[p.JTI] {
			delete(m.queue, id)
			n++
		}
	}
	return n, nil
}

func (m *MemoryStore) Drop(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.queue, id)
	return nil
}
