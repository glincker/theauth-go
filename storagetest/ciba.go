package storagetest

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
)

// RunCIBA runs the CIBAStorage contract tests (RFC 9509 backchannel
// requests). newUser returns the id of a user that exists in the store, for
// backends that enforce a foreign key on the approving user.
func RunCIBA(t *testing.T, store theauth.CIBAStorage, newUser func(t *testing.T) theauth.ULID) {
	t.Helper()
	t.Run("CIBA", func(t *testing.T) { testCIBA(t, store, newUser) })
}

func testCIBA(t *testing.T, store theauth.CIBAStorage, newUser func(t *testing.T) theauth.ULID) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	mk := func(id string) theauth.BackchannelRequest {
		return theauth.BackchannelRequest{
			AuthReqID: id, ClientID: "client-1", LoginHint: "alice@example.com",
			Scope: []string{"openid", "pay"}, BindingMessage: "Approve 10 USD",
			ClientNotificationToken: "cnt", Status: theauth.BackchannelStatusPending,
			PollInterval: 5, ExpiresAt: now.Add(5 * time.Minute), CreatedAt: now,
		}
	}

	t.Run("insert and get round trip", func(t *testing.T) {
		in := mk("req-roundtrip")
		if err := store.InsertBackchannelRequest(ctx, in); err != nil {
			t.Fatalf("insert: %v", err)
		}
		got, err := store.BackchannelRequestByID(ctx, in.AuthReqID)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if got.ClientID != in.ClientID || got.LoginHint != in.LoginHint || got.BindingMessage != in.BindingMessage ||
			got.ClientNotificationToken != in.ClientNotificationToken || got.Status != in.Status ||
			got.PollInterval != in.PollInterval || !reflect.DeepEqual(got.Scope, in.Scope) {
			t.Fatalf("round trip mismatch: %+v", got)
		}
		if got.UserID != nil || got.LastPollAt != nil {
			t.Fatalf("expected nil user and last poll, got %+v", got)
		}
		if !got.ExpiresAt.Equal(in.ExpiresAt) || !got.CreatedAt.Equal(in.CreatedAt) {
			t.Fatalf("time mismatch: %v %v", got.ExpiresAt, got.CreatedAt)
		}
	})
	t.Run("unknown id is not found", func(t *testing.T) {
		if _, err := store.BackchannelRequestByID(ctx, "nope"); !errors.Is(err, theauth.ErrStorageNotFound) {
			t.Fatalf("get: want ErrStorageNotFound, got %v", err)
		}
		if err := store.UpdateBackchannelRequest(ctx, mk("nope")); !errors.Is(err, theauth.ErrStorageNotFound) {
			t.Fatalf("update: want ErrStorageNotFound, got %v", err)
		}
		if err := store.DeleteBackchannelRequest(ctx, "nope"); !errors.Is(err, theauth.ErrStorageNotFound) {
			t.Fatalf("delete: want ErrStorageNotFound, got %v", err)
		}
		if _, err := store.TouchBackchannelPoll(ctx, "nope", now, 5); !errors.Is(err, theauth.ErrStorageNotFound) {
			t.Fatalf("touch: want ErrStorageNotFound, got %v", err)
		}
	})
	t.Run("approve persists user and tokens", func(t *testing.T) {
		req := mk("req-approve")
		if err := store.InsertBackchannelRequest(ctx, req); err != nil {
			t.Fatalf("insert: %v", err)
		}
		uid := newUser(t)
		req.UserID = &uid
		req.Status = theauth.BackchannelStatusApproved
		req.AccessToken, req.RefreshToken = "at", "rt"
		if err := store.UpdateBackchannelRequest(ctx, req); err != nil {
			t.Fatalf("update: %v", err)
		}
		got, err := store.BackchannelRequestByID(ctx, req.AuthReqID)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if got.Status != theauth.BackchannelStatusApproved || got.AccessToken != "at" || got.RefreshToken != "rt" ||
			got.UserID == nil || *got.UserID != uid {
			t.Fatalf("approve not persisted: %+v", got)
		}
		if !got.CreatedAt.Equal(now) {
			t.Fatalf("created_at changed: %v", got.CreatedAt)
		}
	})
	t.Run("touch poll records time and interval", func(t *testing.T) {
		req := mk("req-touch")
		if err := store.InsertBackchannelRequest(ctx, req); err != nil {
			t.Fatalf("insert: %v", err)
		}
		at := now.Add(time.Second)
		got, err := store.TouchBackchannelPoll(ctx, req.AuthReqID, at, 10)
		if err != nil {
			t.Fatalf("touch: %v", err)
		}
		if got.PollInterval != 10 || got.LastPollAt == nil || !got.LastPollAt.Equal(at) {
			t.Fatalf("touch result: %+v", got)
		}
		again, err := store.BackchannelRequestByID(ctx, req.AuthReqID)
		if err != nil || again.PollInterval != 10 || again.LastPollAt == nil || !again.LastPollAt.Equal(at) {
			t.Fatalf("touch not persisted: %+v %v", again, err)
		}
	})
	t.Run("delete removes the row", func(t *testing.T) {
		req := mk("req-delete")
		if err := store.InsertBackchannelRequest(ctx, req); err != nil {
			t.Fatalf("insert: %v", err)
		}
		if err := store.DeleteBackchannelRequest(ctx, req.AuthReqID); err != nil {
			t.Fatalf("delete: %v", err)
		}
		if _, err := store.BackchannelRequestByID(ctx, req.AuthReqID); !errors.Is(err, theauth.ErrStorageNotFound) {
			t.Fatalf("after delete: %v", err)
		}
	})
}

// CIBARedeemStore is the storage surface RunCIBARedeem needs: the CIBA
// contract plus the optional single use redeem capability.
type CIBARedeemStore interface {
	theauth.CIBAStorage
	theauth.BackchannelRedeemer
}

// RunCIBARedeem runs the BackchannelRedeemer contract: an approved, unexpired
// request is redeemed by exactly one of many concurrent callers, and pending,
// denied, expired, consumed and unknown requests are refused without error.
func RunCIBARedeem(t *testing.T, store CIBARedeemStore) {
	t.Helper()
	t.Run("CIBARedeem", func(t *testing.T) { testCIBARedeem(t, store) })
}

func testCIBARedeem(t *testing.T, store CIBARedeemStore) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	insert := func(t *testing.T, id, status string) theauth.BackchannelRequest {
		t.Helper()
		req := theauth.BackchannelRequest{
			AuthReqID: id, ClientID: "client-redeem", Scope: []string{"openid"},
			Status: theauth.BackchannelStatusPending, PollInterval: 5,
			ExpiresAt: now.Add(time.Hour), CreatedAt: now,
		}
		if err := store.InsertBackchannelRequest(ctx, req); err != nil {
			t.Fatalf("insert: %v", err)
		}
		if status != theauth.BackchannelStatusPending {
			req.Status = status
			if status == theauth.BackchannelStatusApproved {
				req.AccessToken, req.RefreshToken = "at-"+id, "rt-"+id
			}
			if err := store.UpdateBackchannelRequest(ctx, req); err != nil {
				t.Fatalf("update: %v", err)
			}
		}
		return req
	}
	refused := func(t *testing.T, id string, at time.Time) {
		t.Helper()
		if _, ok, err := store.RedeemBackchannelRequest(ctx, id, at); err != nil || ok {
			t.Fatalf("redeem %s: want ok=false err=nil, got ok=%v err=%v", id, ok, err)
		}
	}

	t.Run("approved redeems once with tokens", func(t *testing.T) {
		insert(t, "redeem-once", theauth.BackchannelStatusApproved)
		got, ok, err := store.RedeemBackchannelRequest(ctx, "redeem-once", now)
		if err != nil || !ok {
			t.Fatalf("redeem: ok=%v err=%v", ok, err)
		}
		if got.AccessToken != "at-redeem-once" || got.RefreshToken != "rt-redeem-once" || got.Status != theauth.BackchannelStatusConsumed {
			t.Fatalf("payload: %+v", got)
		}
		stored, err := store.BackchannelRequestByID(ctx, "redeem-once")
		if err != nil || stored.Status != theauth.BackchannelStatusConsumed {
			t.Fatalf("stored: %+v %v", stored, err)
		}
		refused(t, "redeem-once", now)
	})
	t.Run("single winner under concurrency", func(t *testing.T) {
		insert(t, "redeem-race", theauth.BackchannelStatusApproved)
		const n = 32
		var wins, failures atomic.Int32
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				_, ok, err := store.RedeemBackchannelRequest(ctx, "redeem-race", now)
				switch {
				case err != nil:
					failures.Add(1)
				case ok:
					wins.Add(1)
				}
			}()
		}
		close(start)
		wg.Wait()
		if failures.Load() != 0 || wins.Load() != 1 {
			t.Fatalf("wins=%d failures=%d, want 1 and 0", wins.Load(), failures.Load())
		}
	})
	t.Run("refuses pending denied expired and unknown", func(t *testing.T) {
		insert(t, "redeem-pending", theauth.BackchannelStatusPending)
		refused(t, "redeem-pending", now)
		insert(t, "redeem-denied", theauth.BackchannelStatusDenied)
		refused(t, "redeem-denied", now)
		exp := insert(t, "redeem-expired", theauth.BackchannelStatusApproved)
		refused(t, "redeem-expired", exp.ExpiresAt.Add(time.Second))
		refused(t, "redeem-unknown", now)
		stored, err := store.BackchannelRequestByID(ctx, "redeem-expired")
		if err != nil || stored.Status != theauth.BackchannelStatusApproved {
			t.Fatalf("refused redeem changed the row: %+v %v", stored, err)
		}
	})
}
