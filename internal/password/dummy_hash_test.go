package password

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/glincker/theauth-go/v2/crypto"
	"github.com/glincker/theauth-go/v2/internal/models"
)

type unknownUserStorage struct{ Storage }

func (unknownUserStorage) UserByEmailWithPassword(context.Context, string) (*models.User, string, error) {
	return nil, "", models.ErrStorageNotFound
}

func countDummyHashes(t *testing.T) *atomic.Int32 {
	t.Helper()
	var n atomic.Int32
	orig := hashDummy
	hashDummy = func(p string) (string, error) {
		n.Add(1)
		return crypto.HashPassword(p)
	}
	t.Cleanup(func() { hashDummy = orig })
	return &n
}

func TestDummyHashLazyAndOnce(t *testing.T) {
	n := countDummyHashes(t)
	svc, err := NewService(unknownUserStorage{}, nil, nil, nil, nil, nil, Config{})
	if err != nil {
		t.Fatal(err)
	}
	if got := n.Load(); got != 0 {
		t.Fatalf("hash computed at construction: %d", got)
	}
	for i := 0; i < 2; i++ {
		_, _, _, err := svc.Signin(context.Background(), "nobody@example.com", "pw", "ua", "1.2.3.4")
		if err == nil {
			t.Fatal("expected invalid credentials")
		}
	}
	if got := n.Load(); got != 1 {
		t.Fatalf("hash computed %d times, want 1", got)
	}
	// Production parameters stay unchanged: 64 MiB, 3 passes, 4 lanes.
	if h := svc.DummyHash(); !strings.HasPrefix(h, "$argon2id$v=19$m=65536,t=3,p=4$") {
		t.Fatalf("unexpected dummy hash parameters: %.40s", h)
	}
}

func TestDummyHashSharedAcrossServices(t *testing.T) {
	n := countDummyHashes(t)
	sharedDummy = &dummyHolder{}
	for i := 0; i < 3; i++ {
		svc, err := NewService(unknownUserStorage{}, nil, nil, nil, nil, nil, Config{ShareDummyHash: true})
		if err != nil {
			t.Fatal(err)
		}
		_ = svc.DummyHash()
	}
	if got := n.Load(); got != 1 {
		t.Fatalf("shared hash computed %d times, want 1", got)
	}
}

func TestDummyHashWarmOnceThenSigninReuses(t *testing.T) {
	n := countDummyHashes(t)
	svc, err := NewService(unknownUserStorage{}, nil, nil, nil, nil, nil, Config{})
	if err != nil {
		t.Fatal(err)
	}
	if got := n.Load(); got != 0 {
		t.Fatalf("hash computed at construction: %d", got)
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = svc.DummyHash()
		}()
	}
	wg.Wait()
	_ = svc.DummyHash()
	if got := n.Load(); got != 1 {
		t.Fatalf("warm computed %d times, want 1", got)
	}
	if _, _, _, err := svc.Signin(context.Background(), "nobody@example.com", "pw", "ua", "1.2.3.4"); err == nil {
		t.Fatal("expected invalid credentials")
	}
	if got := n.Load(); got != 1 {
		t.Fatalf("signin recomputed the hash: %d", got)
	}
}
