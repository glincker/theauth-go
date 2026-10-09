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

// RunDeviceAuthorizations runs the contract tests for the OAuth device grant
// (RFC 8628) storage extension. It is unrelated to RunDeviceCodes, which covers
// the API-token device flow.
func RunDeviceAuthorizations(t *testing.T, store theauth.DeviceAuthorizationStorage) {
	t.Helper()
	t.Run("DeviceAuthorizations", func(t *testing.T) { testDeviceAuthorizations(t, store) })
}

// RunRegistrationTokens runs the contract tests for initial access token
// storage.
func RunRegistrationTokens(t *testing.T, store theauth.RegistrationTokenStorage) {
	t.Helper()
	t.Run("RegistrationTokens", func(t *testing.T) { testRegistrationTokens(t, store) })
}

func newDeviceAuthz(tag string, now time.Time) theauth.DeviceAuthorization {
	return theauth.DeviceAuthorization{
		ID:              newID(),
		DeviceCodeHash:  sha256Hash([]byte("device-" + tag)),
		UserCodeHash:    sha256Hash([]byte("user-" + tag)),
		ClientID:        "client-" + tag,
		Scope:           []string{"read", "deploy"},
		Resource:        "https://api.example.com",
		Status:          theauth.DeviceAuthPending,
		IntervalSeconds: 5,
		CreatedAt:       now,
		ExpiresAt:       now.Add(10 * time.Minute),
	}
}

func testDeviceAuthorizations(t *testing.T, store theauth.DeviceAuthorizationStorage) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	suffix := newID().String()
	user := newID()

	t.Run("insert and look up by either code", func(t *testing.T) {
		d := newDeviceAuthz("a-"+suffix, now)
		if err := store.InsertDeviceAuthorization(ctx, d); err != nil {
			t.Fatalf("insert: %v", err)
		}
		byDevice, err := store.DeviceAuthorizationByDeviceCodeHash(ctx, d.DeviceCodeHash)
		if err != nil || byDevice.ID != d.ID || byDevice.ClientID != d.ClientID ||
			len(byDevice.Scope) != 2 || byDevice.Resource != d.Resource ||
			byDevice.Status != theauth.DeviceAuthPending || byDevice.IntervalSeconds != 5 ||
			!byDevice.ExpiresAt.Equal(d.ExpiresAt) || byDevice.UserID != nil || byDevice.LastPollAt != nil {
			t.Fatalf("by device hash: %+v %v", byDevice, err)
		}
		byUser, err := store.DeviceAuthorizationByUserCodeHash(ctx, d.UserCodeHash)
		if err != nil || byUser.ID != d.ID || !bytes.Equal(byUser.DeviceCodeHash, d.DeviceCodeHash) {
			t.Fatalf("by user hash: %+v %v", byUser, err)
		}
		if _, err := store.DeviceAuthorizationByDeviceCodeHash(ctx, sha256Hash([]byte("nope"+suffix))); !errors.Is(err, theauth.ErrStorageNotFound) {
			t.Fatalf("device miss: got %v", err)
		}
		if _, err := store.DeviceAuthorizationByUserCodeHash(ctx, sha256Hash([]byte("nope"+suffix))); !errors.Is(err, theauth.ErrStorageNotFound) {
			t.Fatalf("user miss: got %v", err)
		}
	})

	t.Run("user code collisions are rejected until expiry", func(t *testing.T) {
		d := newDeviceAuthz("b-"+suffix, now)
		if err := store.InsertDeviceAuthorization(ctx, d); err != nil {
			t.Fatal(err)
		}
		dup := newDeviceAuthz("b2-"+suffix, now)
		dup.UserCodeHash = d.UserCodeHash
		if err := store.InsertDeviceAuthorization(ctx, dup); !errors.Is(err, theauth.ErrDeviceAuthUserCodeTaken) {
			t.Fatalf("live duplicate: got %v", err)
		}
		// An expired holder does not block reuse of the code.
		old := newDeviceAuthz("c-"+suffix, now.Add(-2*time.Hour))
		if err := store.InsertDeviceAuthorization(ctx, old); err != nil {
			t.Fatal(err)
		}
		reuse := newDeviceAuthz("c2-"+suffix, now)
		reuse.UserCodeHash = old.UserCodeHash
		if err := store.InsertDeviceAuthorization(ctx, reuse); err != nil {
			t.Fatalf("reuse after expiry: %v", err)
		}
		got, err := store.DeviceAuthorizationByUserCodeHash(ctx, old.UserCodeHash)
		if err != nil || got.ID != reuse.ID {
			t.Fatalf("lookup must prefer the live record: %+v %v", got, err)
		}
	})

	t.Run("decide is compare and set", func(t *testing.T) {
		d := newDeviceAuthz("d-"+suffix, now)
		_ = store.InsertDeviceAuthorization(ctx, d)
		ok, err := store.DecideDeviceAuthorization(ctx, d.ID, theauth.DeviceAuthApproved, user, now)
		if err != nil || !ok {
			t.Fatalf("first decide: %v %v", ok, err)
		}
		ok, err = store.DecideDeviceAuthorization(ctx, d.ID, theauth.DeviceAuthDenied, user, now)
		if err != nil || ok {
			t.Fatalf("second decide must lose: %v %v", ok, err)
		}
		got, _ := store.DeviceAuthorizationByDeviceCodeHash(ctx, d.DeviceCodeHash)
		if got.Status != theauth.DeviceAuthApproved || got.UserID == nil || *got.UserID != user || got.DecidedAt == nil {
			t.Fatalf("decision not recorded: %+v", got)
		}
	})

	t.Run("decide refuses expired records", func(t *testing.T) {
		d := newDeviceAuthz("e-"+suffix, now)
		_ = store.InsertDeviceAuthorization(ctx, d)
		ok, err := store.DecideDeviceAuthorization(ctx, d.ID, theauth.DeviceAuthApproved, user, d.ExpiresAt.Add(time.Second))
		if err != nil || ok {
			t.Fatalf("expired decide: %v %v", ok, err)
		}
	})

	t.Run("consume needs approval and has one winner", func(t *testing.T) {
		d := newDeviceAuthz("f-"+suffix, now)
		_ = store.InsertDeviceAuthorization(ctx, d)
		if ok, err := store.ConsumeDeviceAuthorization(ctx, d.ID, now); err != nil || ok {
			t.Fatalf("consume while pending: %v %v", ok, err)
		}
		_, _ = store.DecideDeviceAuthorization(ctx, d.ID, theauth.DeviceAuthApproved, user, now)
		var wins atomic.Int32
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if ok, err := store.ConsumeDeviceAuthorization(ctx, d.ID, now); err == nil && ok {
					wins.Add(1)
				}
			}()
		}
		wg.Wait()
		if wins.Load() != 1 {
			t.Fatalf("consume winners = %d, want 1", wins.Load())
		}
		got, _ := store.DeviceAuthorizationByDeviceCodeHash(ctx, d.DeviceCodeHash)
		if got.Status != theauth.DeviceAuthConsumed {
			t.Fatalf("status = %s", got.Status)
		}
	})

	t.Run("denied records cannot be consumed", func(t *testing.T) {
		d := newDeviceAuthz("g-"+suffix, now)
		_ = store.InsertDeviceAuthorization(ctx, d)
		_, _ = store.DecideDeviceAuthorization(ctx, d.ID, theauth.DeviceAuthDenied, user, now)
		if ok, _ := store.ConsumeDeviceAuthorization(ctx, d.ID, now); ok {
			t.Fatal("denied record was consumed")
		}
	})

	t.Run("poll bookkeeping", func(t *testing.T) {
		d := newDeviceAuthz("h-"+suffix, now)
		_ = store.InsertDeviceAuthorization(ctx, d)
		polled := now.Add(3 * time.Second)
		if err := store.RecordDeviceAuthorizationPoll(ctx, d.ID, polled, 10); err != nil {
			t.Fatal(err)
		}
		got, _ := store.DeviceAuthorizationByDeviceCodeHash(ctx, d.DeviceCodeHash)
		if got.LastPollAt == nil || !got.LastPollAt.Equal(polled) || got.IntervalSeconds != 10 {
			t.Fatalf("poll not recorded: %+v", got)
		}
	})

	t.Run("delete expired", func(t *testing.T) {
		d := newDeviceAuthz("i-"+suffix, now.Add(-3*time.Hour))
		_ = store.InsertDeviceAuthorization(ctx, d)
		n, err := store.DeleteExpiredDeviceAuthorizations(ctx, now.Add(-time.Hour))
		if err != nil || n < 1 {
			t.Fatalf("delete: n=%d err=%v", n, err)
		}
		if _, err := store.DeviceAuthorizationByDeviceCodeHash(ctx, d.DeviceCodeHash); !errors.Is(err, theauth.ErrStorageNotFound) {
			t.Fatalf("row survived: %v", err)
		}
	})
}

func newRegToken(tag string, now time.Time, org *theauth.ULID) theauth.RegistrationToken {
	return theauth.RegistrationToken{
		ID:             newID(),
		TokenHash:      sha256Hash([]byte("reg-" + tag)),
		Prefix:         "rt_abcd",
		Label:          "label-" + tag,
		OrganizationID: org,
		Scopes:         []string{"read"},
		GrantTypes:     []string{"client_credentials"},
		MaxUses:        1,
		CreatedAt:      now,
		ExpiresAt:      now.Add(time.Hour),
	}
}

func testRegistrationTokens(t *testing.T, store theauth.RegistrationTokenStorage) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	suffix := newID().String()
	orgA, orgB := newID(), newID()

	t.Run("insert and look up", func(t *testing.T) {
		tok := newRegToken("a-"+suffix, now, &orgA)
		if err := store.InsertRegistrationToken(ctx, tok); err != nil {
			t.Fatal(err)
		}
		byHash, err := store.RegistrationTokenByHash(ctx, tok.TokenHash)
		if err != nil || byHash.ID != tok.ID || byHash.Label != tok.Label || byHash.Prefix != tok.Prefix ||
			byHash.OrganizationID == nil || *byHash.OrganizationID != orgA ||
			len(byHash.Scopes) != 1 || len(byHash.GrantTypes) != 1 || byHash.MaxUses != 1 || byHash.Uses != 0 ||
			!byHash.ExpiresAt.Equal(tok.ExpiresAt) {
			t.Fatalf("by hash: %+v %v", byHash, err)
		}
		byID, err := store.RegistrationTokenByID(ctx, tok.ID)
		if err != nil || !bytes.Equal(byID.TokenHash, tok.TokenHash) {
			t.Fatalf("by id: %+v %v", byID, err)
		}
		if _, err := store.RegistrationTokenByHash(ctx, sha256Hash([]byte("x"+suffix))); !errors.Is(err, theauth.ErrStorageNotFound) {
			t.Fatalf("miss: %v", err)
		}
	})

	t.Run("list filters by organization, newest first", func(t *testing.T) {
		first := newRegToken("l1-"+suffix, now.Add(-time.Minute), &orgB)
		second := newRegToken("l2-"+suffix, now, &orgB)
		other := newRegToken("l3-"+suffix, now, &orgA)
		for _, tok := range []theauth.RegistrationToken{first, second, other} {
			if err := store.InsertRegistrationToken(ctx, tok); err != nil {
				t.Fatal(err)
			}
		}
		got, err := store.ListRegistrationTokens(ctx, &orgB)
		if err != nil || len(got) != 2 || got[0].ID != second.ID || got[1].ID != first.ID {
			t.Fatalf("org list: %+v %v", got, err)
		}
		all, err := store.ListRegistrationTokens(ctx, nil)
		if err != nil || len(all) < 4 {
			t.Fatalf("unfiltered list: %d %v", len(all), err)
		}
	})

	t.Run("redeem honors max uses, expiry and revocation", func(t *testing.T) {
		tok := newRegToken("r-"+suffix, now, &orgA)
		tok.MaxUses = 2
		_ = store.InsertRegistrationToken(ctx, tok)
		for i, want := range []bool{true, true, false} {
			ok, err := store.RedeemRegistrationToken(ctx, tok.ID, now)
			if err != nil || ok != want {
				t.Fatalf("redeem %d: got %v err %v want %v", i, ok, err, want)
			}
		}
		got, _ := store.RegistrationTokenByID(ctx, tok.ID)
		if got.Uses != 2 || got.LastUsedAt == nil {
			t.Fatalf("usage not recorded: %+v", got)
		}
		if err := store.RefundRegistrationToken(ctx, tok.ID); err != nil {
			t.Fatal(err)
		}
		if ok, _ := store.RedeemRegistrationToken(ctx, tok.ID, now); !ok {
			t.Fatal("refund should free a use")
		}

		expired := newRegToken("re-"+suffix, now, &orgA)
		_ = store.InsertRegistrationToken(ctx, expired)
		if ok, _ := store.RedeemRegistrationToken(ctx, expired.ID, expired.ExpiresAt.Add(time.Second)); ok {
			t.Fatal("expired token redeemed")
		}

		revoked := newRegToken("rr-"+suffix, now, &orgA)
		_ = store.InsertRegistrationToken(ctx, revoked)
		if ok, err := store.RevokeRegistrationToken(ctx, revoked.ID, now); err != nil || !ok {
			t.Fatalf("revoke: %v %v", ok, err)
		}
		if ok, _ := store.RevokeRegistrationToken(ctx, revoked.ID, now); ok {
			t.Fatal("second revoke should report no change")
		}
		if ok, _ := store.RedeemRegistrationToken(ctx, revoked.ID, now); ok {
			t.Fatal("revoked token redeemed")
		}
	})

	t.Run("a one-time token has one winner", func(t *testing.T) {
		tok := newRegToken("w-"+suffix, now, &orgA)
		_ = store.InsertRegistrationToken(ctx, tok)
		var wins atomic.Int32
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if ok, err := store.RedeemRegistrationToken(ctx, tok.ID, now); err == nil && ok {
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
