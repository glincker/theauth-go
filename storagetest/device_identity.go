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

	t.Run("attestation claims round trip", func(t *testing.T) {
		d := newIoTDevice("claims-"+suffix, now, &orgA)
		d.AttestationClaims = map[string]any{
			"format": "android-key-attestation", "securityLevel": "strongbox", "deviceLocked": true,
			"packages": []any{"com.example.app"},
		}
		if err := store.InsertDevice(ctx, d); err != nil {
			t.Fatal(err)
		}
		got, err := store.DeviceByID(ctx, d.ID)
		if err != nil || got.AttestationClaims["securityLevel"] != "strongbox" || got.AttestationClaims["deviceLocked"] != true ||
			len(got.AttestationClaims["packages"].([]any)) != 1 {
			t.Fatalf("claims: %+v %v", got.AttestationClaims, err)
		}
		plain := newIoTDevice("noclaims-"+suffix, now, &orgA)
		if err := store.InsertDevice(ctx, plain); err != nil {
			t.Fatal(err)
		}
		got, err = store.DeviceByID(ctx, plain.ID)
		if err != nil || len(got.AttestationClaims) != 0 {
			t.Fatalf("no claims: %+v %v", got.AttestationClaims, err)
		}
		list, err := store.ListDevices(ctx, &orgA)
		if err != nil {
			t.Fatal(err)
		}
		seen := false
		for _, l := range list {
			if l.ID == d.ID && l.AttestationClaims["securityLevel"] == "strongbox" {
				seen = true
			}
		}
		if !seen {
			t.Fatal("list lost the claims")
		}
	})

	t.Run("app attest counter only grows and one racer wins", func(t *testing.T) {
		counters, ok := store.(theauth.DeviceAppAttestStorage)
		if !ok {
			t.Skip("store has no DeviceAppAttestStorage")
		}
		d := newIoTDevice("counter-"+suffix, now, &orgA)
		if err := store.InsertDevice(ctx, d); err != nil {
			t.Fatal(err)
		}
		advance := func(n uint32) bool {
			ok, err := counters.AdvanceAppAttestCounter(ctx, d.ID, n)
			if err != nil {
				t.Fatal(err)
			}
			return ok
		}
		if !advance(1) || advance(1) || advance(0) || !advance(9) || advance(4) {
			t.Fatal("counter did not behave monotonically")
		}
		got, err := store.DeviceByID(ctx, d.ID)
		if err != nil || got.AppAttestCounter != 9 {
			t.Fatalf("stored counter: %+v %v", got, err)
		}
		if ok, err := counters.AdvanceAppAttestCounter(ctx, newID(), 5); err != nil || ok {
			t.Fatalf("unknown device advanced: %v %v", ok, err)
		}
		if !advance(4294967295) || advance(4294967295) {
			t.Fatal("max counter")
		}
		race := newIoTDevice("counter-race-"+suffix, now, &orgA)
		if err := store.InsertDevice(ctx, race); err != nil {
			t.Fatal(err)
		}
		var wins atomic.Int32
		var wg sync.WaitGroup
		for i := 0; i < 12; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if ok, err := counters.AdvanceAppAttestCounter(ctx, race.ID, 7); err == nil && ok {
					wins.Add(1)
				}
			}()
		}
		wg.Wait()
		if wins.Load() != 1 {
			t.Fatalf("%d racers advanced the counter", wins.Load())
		}
	})

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

	t.Run("suspend and resume are conditional", func(t *testing.T) {
		d := newIoTDevice("sr-"+suffix, now, &orgA)
		if err := store.InsertDevice(ctx, d); err != nil {
			t.Fatal(err)
		}
		if ok, err := store.ResumeDevice(ctx, d.ID); err != nil || ok {
			t.Fatalf("resume an active device: %v %v", ok, err)
		}
		if ok, err := store.SuspendDevice(ctx, d.ID); err != nil || !ok {
			t.Fatalf("suspend: %v %v", ok, err)
		}
		if ok, err := store.SuspendDevice(ctx, d.ID); err != nil || ok {
			t.Fatalf("suspend twice: %v %v", ok, err)
		}
		got, _ := store.DeviceByID(ctx, d.ID)
		if got.Status != theauth.DeviceStatusSuspended || got.Active() || got.RevokedAt != nil {
			t.Fatalf("after suspend: %+v", got)
		}
		if ok, err := store.ResumeDevice(ctx, d.ID); err != nil || !ok {
			t.Fatalf("resume: %v %v", ok, err)
		}
		got, _ = store.DeviceByID(ctx, d.ID)
		if !got.Active() {
			t.Fatalf("after resume: %+v", got)
		}
		// A suspended device can still be revoked, and revoked is final.
		if _, err := store.SuspendDevice(ctx, d.ID); err != nil {
			t.Fatal(err)
		}
		if ok, err := store.RevokeDevice(ctx, d.ID, now); err != nil || !ok {
			t.Fatalf("revoke suspended: %v %v", ok, err)
		}
		if ok, err := store.ResumeDevice(ctx, d.ID); err != nil || ok {
			t.Fatalf("resume a revoked device: %v %v", ok, err)
		}
		if ok, err := store.SuspendDevice(ctx, d.ID); err != nil || ok {
			t.Fatalf("suspend a revoked device: %v %v", ok, err)
		}
		got, _ = store.DeviceByID(ctx, d.ID)
		if got.Status != theauth.DeviceStatusRevoked || got.Active() {
			t.Fatalf("revoked device came back: %+v", got)
		}
		if ok, err := store.SuspendDevice(ctx, newID()); err != nil || ok {
			t.Fatalf("suspend unknown: %v %v", ok, err)
		}
	})

	t.Run("concurrent suspend has one winner", func(t *testing.T) {
		d := newIoTDevice("cs-"+suffix, now, &orgA)
		if err := store.InsertDevice(ctx, d); err != nil {
			t.Fatal(err)
		}
		wins := raceWinners(claimRaceWorkers, func() bool {
			ok, err := store.SuspendDevice(ctx, d.ID)
			if err != nil {
				t.Errorf("SuspendDevice: %v", err)
			}
			return ok
		})
		if wins != 1 {
			t.Fatalf("winners = %d, want 1", wins)
		}
	})

	t.Run("lookup by spiffe id and key thumbprint", func(t *testing.T) {
		d := newIoTDevice("lk-"+suffix, now, &orgA)
		if err := store.InsertDevice(ctx, d); err != nil {
			t.Fatal(err)
		}
		got, err := store.DeviceBySPIFFEID(ctx, d.SPIFFEID)
		if err != nil || got.ID != d.ID || got.KeyThumbprint != d.KeyThumbprint {
			t.Fatalf("by spiffe: %+v %v", got, err)
		}
		got, err = store.DeviceByKeyThumbprint(ctx, d.KeyThumbprint)
		if err != nil || got.ID != d.ID {
			t.Fatalf("by thumbprint: %+v %v", got, err)
		}
		for _, miss := range []string{"", "spiffe://example.org/none-" + suffix} {
			if _, err := store.DeviceBySPIFFEID(ctx, miss); !errors.Is(err, theauth.ErrStorageNotFound) {
				t.Fatalf("spiffe miss %q: %v", miss, err)
			}
		}
		for _, miss := range []string{"", "thumb-none-" + suffix} {
			if _, err := store.DeviceByKeyThumbprint(ctx, miss); !errors.Is(err, theauth.ErrStorageNotFound) {
				t.Fatalf("thumbprint miss %q: %v", miss, err)
			}
		}
		// A device without a SPIFFE ID is never found by the empty string.
		n := newIoTDevice("lk2-"+suffix, now, &orgA)
		n.SPIFFEID = ""
		if err := store.InsertDevice(ctx, n); err != nil {
			t.Fatal(err)
		}
		if _, err := store.DeviceBySPIFFEID(ctx, ""); !errors.Is(err, theauth.ErrStorageNotFound) {
			t.Fatalf("empty spiffe matched a device: %v", err)
		}
		// Two devices sharing a key: the newest answers.
		older := newIoTDevice("lk3-"+suffix, now.Add(-time.Hour), &orgA)
		newer := newIoTDevice("lk4-"+suffix, now, &orgA)
		newer.KeyThumbprint = older.KeyThumbprint
		for _, x := range []theauth.Device{older, newer} {
			if err := store.InsertDevice(ctx, x); err != nil {
				t.Fatal(err)
			}
		}
		got, err = store.DeviceByKeyThumbprint(ctx, older.KeyThumbprint)
		if err != nil || got.ID != newer.ID {
			t.Fatalf("shared key: %+v %v", got, err)
		}
	})

	t.Run("bulk join token spends exactly max uses", func(t *testing.T) {
		tok := newJoinToken("b-"+suffix, time.Now().UTC(), &orgA)
		tok.MaxUses = 3
		if err := store.InsertDeviceJoinToken(ctx, tok); err != nil {
			t.Fatal(err)
		}
		got, _ := store.DeviceJoinTokenByID(ctx, tok.ID)
		if got.MaxUses != 3 || got.Uses != 0 || !got.Active(time.Now()) {
			t.Fatalf("fresh bulk token: %+v", got)
		}
		wins := raceWinners(claimRaceWorkers, func() bool {
			ok, err := store.RedeemDeviceJoinToken(ctx, tok.ID, newID(), time.Now().UTC())
			if err != nil {
				t.Errorf("RedeemDeviceJoinToken: %v", err)
			}
			return ok
		})
		if wins != 3 {
			t.Fatalf("DOUBLE SPEND: %d winners on a token with 3 uses", wins)
		}
		got, _ = store.DeviceJoinTokenByID(ctx, tok.ID)
		if got.Uses != 3 || got.RedeemedAt == nil || got.DeviceID != nil || got.Active(time.Now()) {
			t.Fatalf("spent bulk token: %+v", got)
		}
		if err := store.RefundDeviceJoinToken(ctx, tok.ID); err != nil {
			t.Fatal(err)
		}
		got, _ = store.DeviceJoinTokenByID(ctx, tok.ID)
		if got.Uses != 2 || got.RedeemedAt != nil || !got.Active(time.Now()) {
			t.Fatalf("after refund: %+v", got)
		}
		if ok, err := store.RedeemDeviceJoinToken(ctx, tok.ID, newID(), time.Now().UTC()); err != nil || !ok {
			t.Fatalf("redeem the refunded use: %v %v", ok, err)
		}
		if ok, err := store.RedeemDeviceJoinToken(ctx, tok.ID, newID(), time.Now().UTC()); err != nil || ok {
			t.Fatalf("fourth use: %v %v", ok, err)
		}
	})

	t.Run("bulk token stops at revoke and expiry", func(t *testing.T) {
		tok := newJoinToken("br-"+suffix, time.Now().UTC(), &orgA)
		tok.MaxUses = 5
		if err := store.InsertDeviceJoinToken(ctx, tok); err != nil {
			t.Fatal(err)
		}
		if ok, err := store.RedeemDeviceJoinToken(ctx, tok.ID, newID(), time.Now().UTC()); err != nil || !ok {
			t.Fatalf("first use: %v %v", ok, err)
		}
		if ok, err := store.RevokeDeviceJoinToken(ctx, tok.ID, time.Now().UTC()); err != nil || !ok {
			t.Fatalf("revoke: %v %v", ok, err)
		}
		if ok, err := store.RedeemDeviceJoinToken(ctx, tok.ID, newID(), time.Now().UTC()); err != nil || ok {
			t.Fatalf("redeem revoked bulk token: %v %v", ok, err)
		}
		exp := newJoinToken("be-"+suffix, now.Add(-2*time.Hour), &orgA)
		exp.MaxUses, exp.ExpiresAt = 5, now.Add(-time.Hour)
		if err := store.InsertDeviceJoinToken(ctx, exp); err != nil {
			t.Fatal(err)
		}
		if ok, err := store.RedeemDeviceJoinToken(ctx, exp.ID, newID(), time.Now().UTC()); err != nil || ok {
			t.Fatalf("redeem expired bulk token: %v %v", ok, err)
		}
	})
}
