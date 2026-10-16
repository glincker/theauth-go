package as

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2/internal/models"
)

// plainCIBAStore implements CIBAStorage only (no redeemer), over a map.
type plainCIBAStore struct {
	mu   sync.Mutex
	rows map[string]models.BackchannelRequest
}

func (p *plainCIBAStore) InsertBackchannelRequest(_ context.Context, r models.BackchannelRequest) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.rows[r.AuthReqID] = r
	return nil
}

func (p *plainCIBAStore) BackchannelRequestByID(_ context.Context, id string) (models.BackchannelRequest, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	r, ok := p.rows[id]
	if !ok {
		return models.BackchannelRequest{}, models.ErrOAuthInvalidGrant
	}
	return r, nil
}

func (p *plainCIBAStore) UpdateBackchannelRequest(_ context.Context, r models.BackchannelRequest) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.rows[r.AuthReqID] = r
	return nil
}

func (p *plainCIBAStore) DeleteBackchannelRequest(_ context.Context, id string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.rows, id)
	return nil
}

func (p *plainCIBAStore) TouchBackchannelPoll(_ context.Context, id string, _ time.Time, _ int) (models.BackchannelRequest, error) {
	return p.BackchannelRequestByID(context.Background(), id)
}

func TestRedeemBackchannelFallbackSingleWinner(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	st := &plainCIBAStore{rows: map[string]models.BackchannelRequest{}}
	_ = st.InsertBackchannelRequest(ctx, models.BackchannelRequest{
		AuthReqID: "a", Status: models.BackchannelStatusApproved, AccessToken: "at", ExpiresAt: now.Add(time.Minute),
	})
	_ = st.InsertBackchannelRequest(ctx, models.BackchannelRequest{
		AuthReqID: "p", Status: models.BackchannelStatusPending, ExpiresAt: now.Add(time.Minute),
	})
	_ = st.InsertBackchannelRequest(ctx, models.BackchannelRequest{
		AuthReqID: "e", Status: models.BackchannelStatusApproved, ExpiresAt: now.Add(-time.Minute),
	})

	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, ok, err := redeemBackchannel(ctx, st, "a", now)
			if err != nil {
				t.Errorf("redeem: %v", err)
			}
			if ok {
				wins.Add(1)
				if got.AccessToken != "at" {
					t.Errorf("winner payload: %+v", got)
				}
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("wins=%d, want 1", wins.Load())
	}
	for _, id := range []string{"p", "e", "missing"} {
		if _, ok, err := redeemBackchannel(ctx, st, id, now); ok || err != nil {
			t.Fatalf("%s: ok=%v err=%v", id, ok, err)
		}
	}
}
