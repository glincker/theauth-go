package storagetest

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
)

// RunDeviceIdentity runs the contract tests for constrained device identity
// storage: registered devices and single-use join tokens.
func RunDeviceIdentity(t *testing.T, store theauth.DeviceIdentityStorage) {
	t.Helper()
	t.Run("DeviceIdentity", func(t *testing.T) { testDeviceIdentity(t, store) })
}

func newIoTDevice(tag string, now time.Time, org *theauth.ULID) theauth.Device {
	return theauth.Device{
		ID: newID(), OrganizationID: org, Name: "sensor-" + tag, SPIFFEID: "spiffe://example.org/" + tag,
		PublicKeyJWK:  []byte(`{"crv":"P-256","kty":"EC","x":"x-` + tag + `","y":"y-` + tag + `"}`),
		KeyThumbprint: "thumb-" + tag, Attestation: theauth.DeviceAttestationJoinToken,
		Scopes: []string{"telemetry:write", "config:read"}, Status: theauth.DeviceStatusActive, CreatedAt: now,
	}
}

func newJoinToken(tag string, now time.Time, org *theauth.ULID) theauth.DeviceJoinToken {
	return theauth.DeviceJoinToken{
		ID: newID(), TokenHash: sha256Hash([]byte("join-" + tag)), Prefix: "dj_ab12", OrganizationID: org,
		Name: "sensor-" + tag, SPIFFEID: "spiffe://example.org/" + tag, Scopes: []string{"telemetry:write"},
		CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}
}

func testDeviceIdentity(t *testing.T, store theauth.DeviceIdentityStorage) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	suffix := newID().String()
	orgA, orgB := newID(), newID()

	t.Run("insert, look up and round trip", func(t *testing.T) {
		d := newIoTDevice("a-"+suffix, now, &orgA)
		if err := store.InsertDevice(ctx, d); err != nil {
			t.Fatal(err)
		}
		got, err := store.DeviceByID(ctx, d.ID)
		if err != nil || got.Name != d.Name || got.SPIFFEID != d.SPIFFEID || got.KeyThumbprint != d.KeyThumbprint ||
			!bytes.Equal(got.PublicKeyJWK, d.PublicKeyJWK) || len(got.Scopes) != 2 || got.Status != theauth.DeviceStatusActive ||
			got.OrganizationID == nil || *got.OrganizationID != orgA || got.LastSeenAt != nil || got.RevokedAt != nil ||
			!got.Active() {
			t.Fatalf("by id: %+v %v", got, err)
		}
		if _, err := store.DeviceByID(ctx, newID()); !errors.Is(err, theauth.ErrStorageNotFound) {
			t.Fatalf("miss: %v", err)
		}
	})

	t.Run("spiffe id is unique, empty ids are not", func(t *testing.T) {
		d := newIoTDevice("u-"+suffix, now, &orgA)
		if err := store.InsertDevice(ctx, d); err != nil {
			t.Fatal(err)
		}
		dup := newIoTDevice("u2-"+suffix, now, &orgA)
		dup.SPIFFEID = d.SPIFFEID
		if err := store.InsertDevice(ctx, dup); !errors.Is(err, theauth.ErrDeviceConflict) {
			t.Fatalf("duplicate spiffe: %v", err)
		}
		for _, tag := range []string{"n1-", "n2-"} {
			n := newIoTDevice(tag+suffix, now, &orgA)
			n.SPIFFEID = ""
			if err := store.InsertDevice(ctx, n); err != nil {
				t.Fatalf("empty spiffe %s: %v", tag, err)
			}
			got, err := store.DeviceByID(ctx, n.ID)
			if err != nil || got.SPIFFEID != "" {
				t.Fatalf("empty spiffe round trip: %+v %v", got, err)
			}
		}
	})

	t.Run("list filters by organization, newest first", func(t *testing.T) {
		first := newIoTDevice("l1-"+suffix, now.Add(-time.Minute), &orgB)
		second := newIoTDevice("l2-"+suffix, now, &orgB)
		for _, d := range []theauth.Device{first, second} {
			if err := store.InsertDevice(ctx, d); err != nil {
				t.Fatal(err)
			}
		}
		got, err := store.ListDevices(ctx, &orgB)
		if err != nil || len(got) != 2 || got[0].ID != second.ID || got[1].ID != first.ID {
			t.Fatalf("org list: %+v %v", got, err)
		}
		all, err := store.ListDevices(ctx, nil)
		if err != nil || len(all) < 2 {
			t.Fatalf("all: %d %v", len(all), err)
		}
	})

	t.Run("touch and revoke", func(t *testing.T) {
		d := newIoTDevice("r-"+suffix, now, &orgA)
		if err := store.InsertDevice(ctx, d); err != nil {
			t.Fatal(err)
		}
		seen := now.Add(time.Minute)
		if err := store.TouchDevice(ctx, d.ID, seen); err != nil {
			t.Fatal(err)
		}
		got, _ := store.DeviceByID(ctx, d.ID)
		if got.LastSeenAt == nil || !got.LastSeenAt.Equal(seen) {
			t.Fatalf("last seen: %+v", got.LastSeenAt)
		}
		changed, err := store.RevokeDevice(ctx, d.ID, seen)
		if err != nil || !changed {
			t.Fatalf("revoke: %v %v", changed, err)
		}
		again, err := store.RevokeDevice(ctx, d.ID, seen)
		if err != nil || again {
			t.Fatalf("second revoke: %v %v", again, err)
		}
		got, _ = store.DeviceByID(ctx, d.ID)
		if got.Active() || got.RevokedAt == nil || got.Status != theauth.DeviceStatusRevoked {
			t.Fatalf("after revoke: %+v", got)
		}
	})

	t.Run("join token insert, look up, revoke", func(t *testing.T) {
		tok := newJoinToken("j-"+suffix, now, &orgA)
		if err := store.InsertDeviceJoinToken(ctx, tok); err != nil {
			t.Fatal(err)
		}
		byHash, err := store.DeviceJoinTokenByHash(ctx, tok.TokenHash)
		if err != nil || byHash.ID != tok.ID || byHash.SPIFFEID != tok.SPIFFEID || byHash.Name != tok.Name ||
			len(byHash.Scopes) != 1 || byHash.RedeemedAt != nil || !byHash.ExpiresAt.Equal(tok.ExpiresAt) {
			t.Fatalf("by hash: %+v %v", byHash, err)
		}
		byID, err := store.DeviceJoinTokenByID(ctx, tok.ID)
		if err != nil || !bytes.Equal(byID.TokenHash, tok.TokenHash) {
			t.Fatalf("by id: %+v %v", byID, err)
		}
		if _, err := store.DeviceJoinTokenByHash(ctx, sha256Hash([]byte("nope"+suffix))); !errors.Is(err, theauth.ErrStorageNotFound) {
			t.Fatalf("miss: %v", err)
		}
		ok, err := store.RevokeDeviceJoinToken(ctx, tok.ID, now)
		if err != nil || !ok {
			t.Fatalf("revoke: %v %v", ok, err)
		}
		won, err := store.RedeemDeviceJoinToken(ctx, tok.ID, newID(), now)
		if err != nil || won {
			t.Fatalf("redeem revoked: %v %v", won, err)
		}
	})

	t.Run("redeem is single use and refundable", func(t *testing.T) {
		tok := newJoinToken("s-"+suffix, time.Now().UTC(), &orgA)
		if err := store.InsertDeviceJoinToken(ctx, tok); err != nil {
			t.Fatal(err)
		}
		dev := newID()
		won, err := store.RedeemDeviceJoinToken(ctx, tok.ID, dev, time.Now().UTC())
		if err != nil || !won {
			t.Fatalf("first redeem: %v %v", won, err)
		}
		got, _ := store.DeviceJoinTokenByID(ctx, tok.ID)
		if got.RedeemedAt == nil || got.DeviceID == nil || *got.DeviceID != dev || got.Active(time.Now()) {
			t.Fatalf("after redeem: %+v", got)
		}
		again, err := store.RedeemDeviceJoinToken(ctx, tok.ID, newID(), time.Now().UTC())
		if err != nil || again {
			t.Fatalf("second redeem: %v %v", again, err)
		}
		if err := store.RefundDeviceJoinToken(ctx, tok.ID); err != nil {
			t.Fatal(err)
		}
		won, err = store.RedeemDeviceJoinToken(ctx, tok.ID, newID(), time.Now().UTC())
		if err != nil || !won {
			t.Fatalf("redeem after refund: %v %v", won, err)
		}
	})

	t.Run("expired token cannot be redeemed", func(t *testing.T) {
		tok := newJoinToken("e-"+suffix, now.Add(-2*time.Hour), &orgA)
		tok.ExpiresAt = now.Add(-time.Hour)
		if err := store.InsertDeviceJoinToken(ctx, tok); err != nil {
			t.Fatal(err)
		}
		won, err := store.RedeemDeviceJoinToken(ctx, tok.ID, newID(), time.Now().UTC())
		if err != nil || won {
			t.Fatalf("redeem expired: %v %v", won, err)
		}
	})

	t.Run("concurrent redeem has one winner", func(t *testing.T) {
		tok := newJoinToken("c-"+suffix, time.Now().UTC(), &orgA)
		if err := store.InsertDeviceJoinToken(ctx, tok); err != nil {
			t.Fatal(err)
		}
		var wins atomic.Int32
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if ok, err := store.RedeemDeviceJoinToken(ctx, tok.ID, newID(), time.Now().UTC()); err == nil && ok {
					wins.Add(1)
				}
			}()
		}
		wg.Wait()
		if wins.Load() != 1 {
			t.Fatalf("winners = %d, want 1", wins.Load())
		}
	})
}
