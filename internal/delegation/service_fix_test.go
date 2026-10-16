package delegation

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2/internal/models"
)

// raceStore simulates two concurrent revokers: the first read shows the grant
// live, but by the time the conditional UPDATE runs another caller has won.
type raceStore struct {
	Storage
	mu         sync.Mutex
	revokedAt  *time.Time
	staleReads int
	revokeErr  error
}

func (r *raceStore) DelegationGrantByID(context.Context, models.ULID) (*models.DelegationGrant, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	g := &models.DelegationGrant{}
	if r.staleReads > 0 {
		r.staleReads--
		return g, nil
	}
	g.RevokedAt = r.revokedAt
	return g, nil
}

func (r *raceStore) RevokeDelegationGrant(context.Context, models.ULID, time.Time, string) error {
	return r.revokeErr
}

type countEmitter struct {
	mu sync.Mutex
	n  int
}

func (c *countEmitter) EmitAudit(context.Context, string, models.TargetRef, map[string]any) {
	c.mu.Lock()
	c.n++
	c.mu.Unlock()
}

func TestRevokeDelegationConditional(t *testing.T) {
	now := time.Now()
	boom := errors.New("db down")
	tests := []struct {
		name       string
		store      *raceStore
		wantErr    error
		wantAudits int
	}{
		{"normal revoke emits once", &raceStore{}, nil, 1},
		{"lost race is a no-op without duplicate event", &raceStore{staleReads: 1, revokedAt: &now, revokeErr: models.ErrStorageNotFound}, nil, 0},
		{"not found and still live surfaces error", &raceStore{revokeErr: models.ErrStorageNotFound}, models.ErrStorageNotFound, 0},
		{"other storage error is wrapped", &raceStore{revokeErr: boom}, boom, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			em := &countEmitter{}
			svc := New(tc.store, &Config{}, nil, em)
			err := svc.RevokeDelegation(context.Background(), models.ULID{}, "why")
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err=%v want %v", err, tc.wantErr)
			}
			if em.n != tc.wantAudits {
				t.Fatalf("audits=%d want %d", em.n, tc.wantAudits)
			}
		})
	}
}

func TestNilGuards(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name       string
		svc        *Service
		grantByIDs bool // GrantByID needs only storage, not cfg
	}{
		{"nil service", nil, true},
		{"nil storage", &Service{cfg: &Config{}}, true},
		{"nil cfg", &Service{storage: &raceStore{}}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.svc.GrantByID(ctx, models.ULID{}); tc.grantByIDs && err == nil {
				t.Error("GrantByID: want error, got nil")
			}
			if err := tc.svc.RevokeDelegation(ctx, models.ULID{}, ""); err == nil {
				t.Error("RevokeDelegation: want error, got nil")
			}
			if _, err := tc.svc.GrantDelegation(ctx, models.GrantDelegationInput{Resource: "r"}); err == nil {
				t.Error("GrantDelegation: want error, got nil")
			}
		})
	}
	t.Run("nil hooks and emitter do not panic", func(t *testing.T) {
		svc := &Service{storage: &raceStore{}, cfg: &Config{}}
		if err := svc.RevokeDelegation(ctx, models.ULID{}, ""); err != nil {
			t.Fatalf("unexpected err %v", err)
		}
	})
	t.Run("nil resource lookup does not panic", func(t *testing.T) {
		svc := &Service{storage: &raceStore{}, cfg: &Config{}, hooks: nil}
		if _, err := svc.GrantDelegation(ctx, models.GrantDelegationInput{Resource: "r", MaxDurationSeconds: 1}); err == nil {
			t.Fatal("want error")
		}
	})
}
