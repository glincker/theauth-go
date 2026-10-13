// Package storetest is the contract suite for signals.Store implementations.
package storetest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2/signals"
)

// Run exercises a fresh store from newStore against the signals.Store
// contract.
func Run(t *testing.T, newStore func(t *testing.T) signals.Store) {
	t.Helper()
	ctx := context.Background()
	base := time.Unix(1_700_000_000, 0).UTC()

	stream := func(id, recv, method string) signals.Stream {
		return signals.Stream{ID: id, ReceiverID: recv, Status: signals.StatusEnabled, CreatedAt: base, UpdatedAt: base,
			Delivery: signals.DeliveryConfig{Method: method, EndpointURL: "https://r.example/push"}}
	}

	t.Run("stream crud", func(t *testing.T) {
		s := newStore(t)
		if _, err := s.GetStream(ctx, "nope"); !errors.Is(err, signals.ErrNotFound) {
			t.Fatalf("missing stream: %v", err)
		}
		a := stream("a", "r1", signals.MethodPush)
		a.EventsDelivered = []string{signals.EventSessionRevoked}
		if err := s.CreateStream(ctx, a); err != nil {
			t.Fatal(err)
		}
		if err := s.CreateStream(ctx, stream("b", "r2", signals.MethodPoll)); err != nil {
			t.Fatal(err)
		}
		got, err := s.GetStream(ctx, "a")
		if err != nil || got.ReceiverID != "r1" || len(got.EventsDelivered) != 1 || got.Delivery.EndpointURL == "" {
			t.Fatalf("get: %+v %v", got, err)
		}
		if l, _ := s.ListStreams(ctx, "r1"); len(l) != 1 || l[0].ID != "a" {
			t.Fatalf("list r1: %+v", l)
		}
		if l, _ := s.ListStreams(ctx, ""); len(l) != 2 {
			t.Fatalf("list all: %+v", l)
		}
		a.Status = signals.StatusPaused
		if err := s.UpdateStream(ctx, a); err != nil {
			t.Fatal(err)
		}
		if got, _ := s.GetStream(ctx, "a"); got.Status != signals.StatusPaused {
			t.Fatalf("update not persisted: %+v", got)
		}
		if err := s.UpdateStream(ctx, stream("ghost", "r1", signals.MethodPush)); !errors.Is(err, signals.ErrNotFound) {
			t.Fatalf("update missing: %v", err)
		}
		if err := s.DeleteStream(ctx, "a"); err != nil {
			t.Fatal(err)
		}
		if _, err := s.GetStream(ctx, "a"); !errors.Is(err, signals.ErrNotFound) {
			t.Fatalf("deleted stream: %v", err)
		}
	})

	t.Run("subjects", func(t *testing.T) {
		s := newStore(t)
		_ = s.CreateStream(ctx, stream("a", "r1", signals.MethodPush))
		if n, _ := s.CountSubjects(ctx, "a"); n != 0 {
			t.Fatalf("count: %d", n)
		}
		for i := 0; i < 2; i++ { // idempotent add
			if err := s.AddSubject(ctx, "a", "email:x@y.z", []byte(`{"format":"email","email":"x@y.z"}`)); err != nil {
				t.Fatal(err)
			}
		}
		if ok, _ := s.HasSubject(ctx, "a", "email:x@y.z"); !ok {
			t.Fatal("subject missing")
		}
		if ok, _ := s.HasSubject(ctx, "a", "email:q@y.z"); ok {
			t.Fatal("unexpected subject")
		}
		if n, _ := s.CountSubjects(ctx, "a"); n != 1 {
			t.Fatalf("count: %d", n)
		}
		_ = s.RemoveSubject(ctx, "a", "email:x@y.z")
		if n, _ := s.CountSubjects(ctx, "a"); n != 0 {
			t.Fatalf("count after remove: %d", n)
		}
	})

	t.Run("queue", func(t *testing.T) {
		s := newStore(t)
		_ = s.CreateStream(ctx, stream("p", "r1", signals.MethodPush))
		_ = s.CreateStream(ctx, stream("q", "r1", signals.MethodPoll))
		mk := func(id, sid, jti string, push bool, off time.Duration) signals.PendingSET {
			return signals.PendingSET{ID: id, StreamID: sid, JTI: jti, Token: "tok-" + jti, Push: push,
				NextAt: base.Add(off), CreatedAt: base.Add(off)}
		}
		for _, p := range []signals.PendingSET{
			mk("1", "p", "j1", true, 0), mk("2", "p", "j2", true, time.Second), mk("3", "q", "j3", false, 0), mk("4", "q", "j4", false, time.Second),
		} {
			if err := s.Enqueue(ctx, p); err != nil {
				t.Fatal(err)
			}
		}
		due, err := s.DuePush(ctx, base, 10)
		if err != nil || len(due) != 1 || due[0].JTI != "j1" || due[0].Token != "tok-j1" || !due[0].Push {
			t.Fatalf("due@0: %+v %v", due, err)
		}
		if due, _ = s.DuePush(ctx, base.Add(time.Minute), 10); len(due) != 2 || due[0].JTI != "j1" {
			t.Fatalf("due@1m: %+v", due)
		}
		if err := s.MarkAttempt(ctx, "1", 2, base.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		if due, _ = s.DuePush(ctx, base.Add(time.Minute), 10); len(due) != 1 || due[0].JTI != "j2" {
			t.Fatalf("due after backoff: %+v", due)
		}
		pend, _ := s.Pending(ctx, "q", 1)
		if len(pend) != 1 || pend[0].JTI != "j3" {
			t.Fatalf("pending limit: %+v", pend)
		}
		if n, _ := s.CountPending(ctx, "q"); n != 2 {
			t.Fatalf("count pending: %d", n)
		}
		if n, _ := s.Ack(ctx, "q", []string{"j3", "unknown"}); n != 1 {
			t.Fatalf("ack: %d", n)
		}
		if n, _ := s.Ack(ctx, "p", []string{"j4"}); n != 0 {
			t.Fatalf("ack must be stream scoped: %d", n)
		}
		if err := s.Drop(ctx, "2"); err != nil {
			t.Fatal(err)
		}
		if n, _ := s.CountPending(ctx, "p"); n != 1 {
			t.Fatalf("after drop: %d", n)
		}
		// switching delivery method re-tags queued rows
		p, _ := s.GetStream(ctx, "p")
		p.Delivery.Method = signals.MethodPoll
		if err := s.UpdateStream(ctx, p); err != nil {
			t.Fatal(err)
		}
		if due, _ = s.DuePush(ctx, base.Add(24*time.Hour), 10); len(due) != 0 {
			t.Fatalf("poll stream rows must not be pushed: %+v", due)
		}
		_ = s.DeleteStream(ctx, "p")
		if n, _ := s.CountPending(ctx, "p"); n != 0 {
			t.Fatalf("delete must clear queue: %d", n)
		}
	})
}
