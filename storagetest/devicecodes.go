package storagetest

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/glincker/theauth-go"
)

// RunDeviceCodes runs the RFC 8628 device code contract tests.
func RunDeviceCodes(t *testing.T, store theauth.DeviceCodeStorage) {
	t.Helper()
	t.Run("DeviceCodes", func(t *testing.T) { testDeviceCodes(t, store) })
}

func newTestDevice(userCode, secret string, now time.Time) theauth.DeviceCode {
	return theauth.DeviceCode{
		ID: newID(), DeviceCodeHash: sha256Hash([]byte(secret)), UserCode: userCode, Status: theauth.DeviceStatusPending,
		ClientName: "cli", RequestedAbilities: []string{"read", "deploy"}, IntervalSeconds: 5,
		CreatedAt: now, ExpiresAt: now.Add(10 * time.Minute),
	}
}

func testDeviceCodes(t *testing.T, store theauth.DeviceCodeStorage) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	approver := newID()
	suffix := newID().String()[16:]

	t.Run("insert, lookup and user code uniqueness", func(t *testing.T) {
		d := newTestDevice("UC"+suffix, "dev-a-"+suffix, now)
		if err := store.InsertDeviceCode(ctx, d); err != nil {
			t.Fatalf("InsertDeviceCode: %v", err)
		}
		dup := newTestDevice(d.UserCode, "dev-dup-"+suffix, now)
		if err := store.InsertDeviceCode(ctx, dup); !errors.Is(err, theauth.ErrDeviceUserCodeTaken) {
			t.Fatalf("duplicate user code: got %v", err)
		}
		byUser, err := store.DeviceCodeByUserCode(ctx, d.UserCode)
		if err != nil || byUser.ID != d.ID || byUser.Status != theauth.DeviceStatusPending {
			t.Fatalf("ByUserCode: %+v %v", byUser, err)
		}
		byHash, err := store.DeviceCodeByHash(ctx, d.DeviceCodeHash)
		if err != nil || byHash.ID != d.ID || len(byHash.RequestedAbilities) != 2 {
			t.Fatalf("ByHash: %+v %v", byHash, err)
		}
		if _, err := store.DeviceCodeByUserCode(ctx, "MISSING"+suffix); !errors.Is(err, theauth.ErrStorageNotFound) {
			t.Fatalf("miss: got %v", err)
		}
	})

	t.Run("decide is compare and set", func(t *testing.T) {
		d := newTestDevice("DC"+suffix, "dev-b-"+suffix, now)
		_ = store.InsertDeviceCode(ctx, d)
		dec := theauth.DeviceDecision{Approve: true, ApproverID: approver, Abilities: []string{"read"}}
		if err := store.DecideDeviceCode(ctx, d.UserCode, dec, now); err != nil {
			t.Fatalf("DecideDeviceCode: %v", err)
		}
		if err := store.DecideDeviceCode(ctx, d.UserCode, theauth.DeviceDecision{ApproverID: approver}, now); !errors.Is(err, theauth.ErrStorageNotFound) {
			t.Fatalf("second decision must lose: got %v", err)
		}
		got, _ := store.DeviceCodeByUserCode(ctx, d.UserCode)
		if got.Status != theauth.DeviceStatusApproved || got.ApproverID == nil || *got.ApproverID != approver ||
			len(got.ApprovedAbilities) != 1 || got.ApprovedAbilities[0] != "read" {
			t.Fatalf("approval not recorded: %+v", got)
		}
	})

	t.Run("decide rejects expired requests", func(t *testing.T) {
		d := newTestDevice("XC"+suffix, "dev-c-"+suffix, now)
		_ = store.InsertDeviceCode(ctx, d)
		late := d.ExpiresAt.Add(time.Second)
		if err := store.DecideDeviceCode(ctx, d.UserCode, theauth.DeviceDecision{Approve: true, ApproverID: approver, Abilities: []string{"read"}}, late); !errors.Is(err, theauth.ErrStorageNotFound) {
			t.Fatalf("expired decide: got %v", err)
		}
	})

	t.Run("claim succeeds exactly once under contention", func(t *testing.T) {
		d := newTestDevice("CC"+suffix, "dev-d-"+suffix, now)
		_ = store.InsertDeviceCode(ctx, d)
		if _, err := store.ClaimDeviceCode(ctx, d.DeviceCodeHash, now); !errors.Is(err, theauth.ErrStorageNotFound) {
			t.Fatalf("claim before approval must fail: got %v", err)
		}
		_ = store.DecideDeviceCode(ctx, d.UserCode, theauth.DeviceDecision{Approve: true, ApproverID: approver, Abilities: []string{"read"}}, now)

		const workers = 16
		var wg sync.WaitGroup
		var mu sync.Mutex
		wins := 0
		for range workers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := store.ClaimDeviceCode(ctx, d.DeviceCodeHash, now); err == nil {
					mu.Lock()
					wins++
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
		if wins != 1 {
			t.Fatalf("%d claims won, want exactly 1", wins)
		}
		got, _ := store.DeviceCodeByHash(ctx, d.DeviceCodeHash)
		if got.Status != theauth.DeviceStatusRedeemed {
			t.Fatalf("status = %q, want redeemed", got.Status)
		}
	})

	t.Run("claim rejects denied and expired requests", func(t *testing.T) {
		d := newTestDevice("NC"+suffix, "dev-e-"+suffix, now)
		_ = store.InsertDeviceCode(ctx, d)
		_ = store.DecideDeviceCode(ctx, d.UserCode, theauth.DeviceDecision{Approve: false, ApproverID: approver}, now)
		if _, err := store.ClaimDeviceCode(ctx, d.DeviceCodeHash, now); !errors.Is(err, theauth.ErrStorageNotFound) {
			t.Fatalf("claim of denied: got %v", err)
		}
		e := newTestDevice("EC"+suffix, "dev-f-"+suffix, now)
		_ = store.InsertDeviceCode(ctx, e)
		_ = store.DecideDeviceCode(ctx, e.UserCode, theauth.DeviceDecision{Approve: true, ApproverID: approver, Abilities: []string{"read"}}, now)
		if _, err := store.ClaimDeviceCode(ctx, e.DeviceCodeHash, e.ExpiresAt.Add(time.Second)); !errors.Is(err, theauth.ErrStorageNotFound) {
			t.Fatalf("claim of expired: got %v", err)
		}
	})

	t.Run("poll bookkeeping and purge", func(t *testing.T) {
		d := newTestDevice("PC"+suffix, "dev-g-"+suffix, now)
		_ = store.InsertDeviceCode(ctx, d)
		if err := store.RecordDevicePoll(ctx, d.DeviceCodeHash, now.Add(time.Second), 10); err != nil {
			t.Fatalf("RecordDevicePoll: %v", err)
		}
		got, _ := store.DeviceCodeByHash(ctx, d.DeviceCodeHash)
		if got.LastPolledAt == nil || got.IntervalSeconds != 10 {
			t.Fatalf("poll not recorded: %+v", got)
		}
		n, err := store.DeleteExpiredDeviceCodes(ctx, d.ExpiresAt.Add(time.Hour))
		if err != nil || n < 1 {
			t.Fatalf("purge: n=%d err=%v", n, err)
		}
		if _, err := store.DeviceCodeByHash(ctx, d.DeviceCodeHash); !errors.Is(err, theauth.ErrStorageNotFound) {
			t.Fatalf("purged row still present: %v", err)
		}
	})
}
