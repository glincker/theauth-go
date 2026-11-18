package mqttauth

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	theauth "github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/storage/memory"
)

// noScanStore fails the test when anything lists devices, which is what the indexed lookups
// replaced.
type noScanStore struct {
	*memory.Store
	t *testing.T
}

func (s noScanStore) ListDevices(context.Context, *theauth.ULID) ([]theauth.Device, error) {
	s.t.Error("ListDevices called: lookups must use the indexed storage methods")
	return nil, nil
}

func TestIdentityStoreIndexedLookups(t *testing.T) {
	ctx := context.Background()
	mem := memory.New()
	d := newRegistryDevice(t, mem, func(d *theauth.Device) {
		d.SPIFFEID = "spiffe://example.org/gw/7"
		d.KeyThumbprint = "thumb-7"
	})
	is := NewIdentityStore(noScanStore{mem, t})

	got, err := is.DeviceBySubject(ctx, d.SPIFFEID)
	if err != nil || got.ID != d.ID.String() || got.Subject != d.SPIFFEID {
		t.Fatalf("by spiffe: %+v %v", got, err)
	}
	got, err = is.DeviceByKeyThumbprint(ctx, "thumb-7")
	if err != nil || got.ID != d.ID.String() {
		t.Fatalf("by thumbprint: %+v %v", got, err)
	}
	if _, err := is.DeviceBySubject(ctx, "spiffe://example.org/none"); err != ErrDeviceNotFound {
		t.Fatalf("spiffe miss: %v", err)
	}
	if _, err := is.DeviceByKeyThumbprint(ctx, "nope"); err != ErrDeviceNotFound {
		t.Fatalf("thumbprint miss: %v", err)
	}
}

func TestIdentityStoreReportsSuspended(t *testing.T) {
	ctx := context.Background()
	mem := memory.New()
	d := newRegistryDevice(t, mem, nil)
	is := NewIdentityStore(mem)
	if ok, err := mem.SuspendDevice(ctx, d.ID); err != nil || !ok {
		t.Fatalf("suspend: %v %v", ok, err)
	}
	got, err := is.DeviceByID(ctx, d.ID.String())
	if err != nil || got.Status != StatusSuspended {
		t.Fatalf("suspended device = %+v %v", got, err)
	}
	if _, err := mem.RevokeDevice(ctx, d.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	got, _ = is.DeviceByID(ctx, d.ID.String())
	if got.Status != StatusRevoked {
		t.Fatalf("revoked device = %+v", got)
	}
}

func TestMemoryPurgeBroadcaster(t *testing.T) {
	var b MemoryPurgeBroadcaster
	ctx, cancel := context.WithCancel(context.Background())
	var got atomic.Value
	got.Store([]string(nil))
	var n atomic.Int32
	done := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			done <- b.Subscribe(ctx, func(id string) { n.Add(1); got.Store([]string{id}) })
		}()
	}
	waitFor(t, func() bool { b.mu.Lock(); defer b.mu.Unlock(); return len(b.subs) == 2 })
	if err := b.Publish(ctx, "dev-9"); err != nil {
		t.Fatal(err)
	}
	if n.Load() != 2 || got.Load().([]string)[0] != "dev-9" {
		t.Fatalf("subscribers called %d times, last %v", n.Load(), got.Load())
	}
	cancel()
	for i := 0; i < 2; i++ {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	if err := b.Publish(context.Background(), "x"); err != nil || n.Load() != 2 {
		t.Fatalf("publish after unsubscribe reached someone: %v %d", err, n.Load())
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestPurgeReachesOtherReplica runs two broker auth replicas over one registry. Replica A handles
// the suspend and the revoke, replica B only learns through the broadcaster. B caches for an hour,
// so an immediate deny on B is the purge.
func TestPurgeReachesOtherReplica(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st := memory.New()
	d := newRegistryDevice(t, st, nil)
	id := d.ID.String()
	key := []byte("jwt-key-0123456789")
	bus := &MemoryPurgeBroadcaster{}

	newReplica := func(p *Purger) *Handler {
		h, err := New(Config{
			Store: NewIdentityStore(st), BrokerSecret: brokerSecret, AllowSampleRate: 1, CacheTTL: time.Hour,
			JWT: &JWTConfig{
				Keyfunc: func(*jwt.Token) (any, error) { return key, nil },
				Methods: []string{"HS256"}, Issuer: "https://auth.example.com", Audience: "mqtt",
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		p.Bind(h)
		p.SetBroadcaster(bus)
		go func() { _ = p.Run(ctx) }()
		return h
	}
	var purgeA, purgeB Purger
	hA, hB := newReplica(&purgeA), newReplica(&purgeB)
	waitFor(t, func() bool { bus.mu.Lock(); defer bus.mu.Unlock(); return len(bus.subs) == 2 })

	enc := make([]byte, 32)
	if _, err := rand.Read(enc); err != nil {
		t.Fatal(err)
	}
	a, err := theauth.New(theauth.Config{
		Storage: st, BaseURL: "https://auth.example.com", EncryptionKey: enc,
		AuthorizationServer: &theauth.AuthorizationServerConfig{
			Issuer:    "https://auth.example.com",
			Resources: []theauth.ProtectedResource{{Identifier: "https://iot.example.com/api", Scopes: []string{"telemetry:write"}}},
			DeviceTokens: &theauth.DeviceTokensConfig{
				OnRevoke: purgeA.OnRevoke, OnStatusChange: purgeA.OnStatusChange,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)

	authz := func(h *Handler) any {
		body, _ := json.Marshal(map[string]string{
			"device_id": id, "clientid": id, "action": "publish", "topic": "devices/" + id + "/telemetry/t",
		})
		r := httptest.NewRequest(http.MethodPost, "/authz", bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer "+brokerSecret)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return out["result"]
	}
	if authz(hA) != "allow" || authz(hB) != "allow" {
		t.Fatal("both replicas should allow an active device")
	}
	if err := a.SuspendDevice(ctx, d.ID); err != nil {
		t.Fatal(err)
	}
	if authz(hB) != "deny" {
		t.Fatal("replica B still allows a suspended device")
	}
	if err := a.ResumeDevice(ctx, d.ID); err != nil {
		t.Fatal(err)
	}
	if authz(hB) != "allow" {
		t.Fatal("replica B still denies a resumed device")
	}
	if err := a.RevokeDevice(ctx, d.ID); err != nil {
		t.Fatal(err)
	}
	if authz(hA) != "deny" || authz(hB) != "deny" {
		t.Fatal("a revoked device is still allowed on a replica")
	}
	// No broadcaster: Run returns at once and OnRevoke stays local.
	var lone Purger
	if err := lone.Run(ctx); err != nil {
		t.Fatalf("Run without broadcaster: %v", err)
	}
}
