package as_test

import (
	"context"
	"crypto/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/storage/memory"
)

func newASInstance(t *testing.T, mut ...func(*theauth.AuthorizationServerConfig)) (*theauth.TheAuth, *memory.Store) {
	t.Helper()
	store := memory.New()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand: %v", err)
	}
	asCfg := &theauth.AuthorizationServerConfig{
		Issuer:          "https://auth.example.com",
		Resources:       []theauth.ProtectedResource{{Identifier: "https://files.example.com/mcp", Scopes: []string{"files.read", "files.write"}}},
		DisableRotation: true,
	}
	for _, m := range mut {
		m(asCfg)
	}
	a, err := theauth.New(theauth.Config{
		Storage:             store,
		BaseURL:             "https://auth.example.com",
		EncryptionKey:       key,
		AuthorizationServer: asCfg,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(a.Close)
	return a, store
}

func TestJWKSBootstrapMintsCurrentAndNext(t *testing.T) {
	_, store := newASInstance(t)
	keys, err := store.JWKSKeysAll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(keys))
	}
	states := map[string]int{}
	for _, k := range keys {
		states[k.State]++
	}
	if states[theauth.JWKSStateCurrent] != 1 || states[theauth.JWKSStateNext] != 1 {
		t.Fatalf("expected one current and one next, got %v", states)
	}
}

func TestRotateSigningKeyAdvancesStateMachine(t *testing.T) {
	a, store := newASInstance(t)
	if err := a.RotateSigningKey(context.Background()); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	keys, _ := store.JWKSKeysAll(context.Background())
	counts := map[string]int{}
	for _, k := range keys {
		counts[k.State]++
	}
	if counts[theauth.JWKSStateCurrent] != 1 {
		t.Fatalf("expected one current after rotation, got %d", counts[theauth.JWKSStateCurrent])
	}
	if counts[theauth.JWKSStatePrevious] != 1 {
		t.Fatalf("expected one previous after rotation, got %d", counts[theauth.JWKSStatePrevious])
	}
	if counts[theauth.JWKSStateNext] != 1 {
		t.Fatalf("expected one next after rotation, got %d", counts[theauth.JWKSStateNext])
	}
}

func TestRotationRace(t *testing.T) {
	a, _ := newASInstance(t)
	var wg sync.WaitGroup
	var failures atomic.Int64
	// Run several rotations sequentially under a writer goroutine while many
	// reader goroutines render the JWKS document. The rotation goroutine
	// itself serialises calls (DisableRotation = true here keeps the
	// background loop off so each RotateSigningKey is operator driven).
	go func() {
		for i := 0; i < 5; i++ {
			if err := a.RotateSigningKey(context.Background()); err != nil {
				failures.Add(1)
			}
		}
	}()
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				if _, err := a.ASMetadataDoc(); err != nil {
					failures.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	if failures.Load() != 0 {
		t.Fatalf("rotation race observed %d failures", failures.Load())
	}
}

func TestNewRejectsASWithoutEncryptionKey(t *testing.T) {
	store := memory.New()
	_, err := theauth.New(theauth.Config{
		Storage:             store,
		BaseURL:             "https://x",
		AuthorizationServer: &theauth.AuthorizationServerConfig{Issuer: "https://auth.example.com"},
	})
	if err == nil {
		t.Fatal("expected ErrASRequiresEncryptionKey")
	}
	if err != theauth.ErrASRequiresEncryptionKey {
		t.Fatalf("expected ErrASRequiresEncryptionKey, got %v", err)
	}
}

func TestNewRejectsASMissingIssuer(t *testing.T) {
	store := memory.New()
	key := make([]byte, 32)
	_, err := theauth.New(theauth.Config{
		Storage:             store,
		BaseURL:             "https://x",
		EncryptionKey:       key,
		AuthorizationServer: &theauth.AuthorizationServerConfig{},
	})
	if err != theauth.ErrASIssuerRequired {
		t.Fatalf("expected ErrASIssuerRequired, got %v", err)
	}
}

func TestNewRejectsRS256(t *testing.T) {
	store := memory.New()
	key := make([]byte, 32)
	_, err := theauth.New(theauth.Config{
		Storage:       store,
		BaseURL:       "https://x",
		EncryptionKey: key,
		AuthorizationServer: &theauth.AuthorizationServerConfig{
			Issuer:     "https://auth.example.com",
			SigningAlg: "RS256",
		},
	})
	if err != theauth.ErrASUnsupportedAlg {
		t.Fatalf("expected ErrASUnsupportedAlg, got %v", err)
	}
}

// TestJWKSRotationConcurrentSafe spawns N goroutines each calling
// RotateSigningKey and asserts that exactly one row has state = current
// when all goroutines finish. This guards against the race that previously
// allowed two rows to hold state = current when rotations interleaved
// between the demote-current and promote-next storage calls (M4, 2026-06-21).
//
// The memory storage backend serialises all JWKS writes under its own mutex,
// so this test exercises the as-package coordination layer. Postgres-specific
// transactional atomicity is validated by the integration suite gated on
// THEAUTH_TEST_PG_DSN.
func TestJWKSRotationConcurrentSafe(t *testing.T) {
	a, store := newASInstance(t)
	const goroutines = 8
	var wg sync.WaitGroup
	errCh := make(chan error, goroutines)
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			if err := a.RotateSigningKey(context.Background()); err != nil {
				errCh <- err
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Errorf("RotateSigningKey error: %v", err)
	}
	keys, err := store.JWKSKeysAll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var currentCount int
	for _, k := range keys {
		if k.State == theauth.JWKSStateCurrent {
			currentCount++
		}
	}
	if currentCount != 1 {
		t.Fatalf("expected exactly 1 current key after concurrent rotations, got %d", currentCount)
	}
}

func TestRotationGoroutineStopsOnClose(t *testing.T) {
	store := memory.New()
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	a, err := theauth.New(theauth.Config{
		Storage:       store,
		BaseURL:       "https://x",
		EncryptionKey: key,
		AuthorizationServer: &theauth.AuthorizationServerConfig{
			Issuer:            "https://auth.example.com",
			KeyRotationPeriod: time.Second,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	a.Close()
	// Close is synchronous and bounded; a second Close is a no-op.
	a.Close()
}
