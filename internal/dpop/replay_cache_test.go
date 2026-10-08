package dpop_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2/internal/dpop"
	"github.com/glincker/theauth-go/v2/kv"
)

type failingReplay struct{}

func (failingReplay) Seen(context.Context, string, time.Duration) (bool, error) {
	return false, errors.New("backend down")
}

func TestSharedReplayCache(t *testing.T) {
	now := time.Now().UTC()
	params := dpop.VerifyParams{Method: "POST", URL: "https://as.example.com/oauth/token", Now: now}
	withCache := func(rc kv.ReplayCache) func(*dpop.Config) {
		return func(c *dpop.Config) { c.ReplayCache = rc }
	}

	t.Run("a second replica rejects a proof the first accepted", func(t *testing.T) {
		shared := kv.NewMemory()
		replicaA := newService(t, withCache(shared))
		replicaB := newService(t, withCache(shared))
		proof, _, _ := signedProofES256(t, baseClaims(now), nil)
		if _, err := replicaA.Verify(proof, params); err != nil {
			t.Fatalf("replica A: %v", err)
		}
		if _, err := replicaB.Verify(proof, params); !errors.Is(err, dpop.ErrReplay) {
			t.Fatalf("replica B: want ErrReplay, got %v", err)
		}
	})

	t.Run("without a shared cache replicas do not see each other", func(t *testing.T) {
		replicaA, replicaB := newService(t), newService(t)
		proof, _, _ := signedProofES256(t, baseClaims(now), nil)
		if _, err := replicaA.Verify(proof, params); err != nil {
			t.Fatal(err)
		}
		if _, err := replicaB.Verify(proof, params); err != nil {
			t.Fatalf("expected per-process behavior, got %v", err)
		}
	})

	t.Run("backend failure fails closed", func(t *testing.T) {
		svc := newService(t, withCache(failingReplay{}))
		proof, _, _ := signedProofES256(t, baseClaims(now), nil)
		if _, err := svc.Verify(proof, params); !errors.Is(err, dpop.ErrReplayStore) {
			t.Fatalf("want ErrReplayStore, got %v", err)
		}
	})
}
