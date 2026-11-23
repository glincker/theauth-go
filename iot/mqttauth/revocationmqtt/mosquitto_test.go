package revocationmqtt

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2/iot/device"
)

// TestMosquitto runs the publisher and receiver against a real Mosquitto 2 broker. It is skipped
// unless THEAUTH_MOSQUITTO_ADDR is set. The broker needs two users and this ACL:
//
//	user pub        (password THEAUTH_MOSQUITTO_PUB_PASSWORD)  topic write theauth/revocations/#
//	user dev        (password THEAUTH_MOSQUITTO_DEV_PASSWORD)  topic read  theauth/revocations/#
//
// docs/mqtt-auth.md has the docker commands that set this up.
func TestMosquitto(t *testing.T) {
	addr := os.Getenv("THEAUTH_MOSQUITTO_ADDR")
	if addr == "" {
		t.Skip("THEAUTH_MOSQUITTO_ADDR not set")
	}
	pubOpts := ConnectOptions{Addr: addr, ClientID: "theauth-test-pub", Username: "pub", Password: os.Getenv("THEAUTH_MOSQUITTO_PUB_PASSWORD")}
	devOpts := ConnectOptions{Addr: addr, ClientID: "theauth-test-dev", Username: "dev", Password: os.Getenv("THEAUTH_MOSQUITTO_DEV_PASSWORD")}

	iss := newIssuer(t)
	// A topic of its own per run, so a retained message from an earlier run cannot satisfy this one.
	topic := "theauth/revocations/mosq-" + strings.ReplaceAll(time.Now().Format("150405.000000"), ".", "")
	now := time.Now()
	tok := iss.snapshot(t, now, "dev-revoked-1", "dev-suspended-1")

	if err := (&Publisher{Connect: pubOpts, Topic: topic}).Publish(ctxTimeout(t, 10*time.Second), tok); err != nil {
		t.Fatalf("publish: %v", err)
	}

	rcv := &Receiver{Connect: devOpts, Topic: topic, Keys: iss.keys, Owner: testOwner, MaxAge: 5 * time.Minute}
	snap, err := rcv.Receive(ctxTimeout(t, 10*time.Second))
	if err != nil {
		t.Fatalf("receive the retained snapshot: %v", err)
	}
	if snap.Count != 2 || !snap.Contains("dev-revoked-1") || snap.Contains("dev-1") {
		t.Fatalf("unexpected snapshot, count %d", snap.Count)
	}

	t.Run("a device cannot overwrite the retained snapshot", func(t *testing.T) {
		// MQTT 3.1.1 has no negative PUBACK, so a denied publish looks like success to the sender.
		// The ACL must hold anyway: the stored message is unchanged.
		forged := iss.snapshot(t, now.Add(time.Second), "dev-1")
		_ = (&Publisher{Connect: devOpts, Topic: topic}).Publish(ctxTimeout(t, 10*time.Second), forged)
		again := &Receiver{Connect: devOpts, Topic: topic, Keys: iss.keys, Owner: testOwner, MaxAge: 5 * time.Minute}
		got, err := again.Receive(ctxTimeout(t, 10*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		if got.Seq != snap.Seq || got.Count != 2 {
			t.Fatalf("retained snapshot changed: seq %d count %d", got.Seq, got.Count)
		}
	})

	t.Run("the publisher account cannot subscribe", func(t *testing.T) {
		// Mosquitto 2.1 grants a subscription the ACL does not allow (MQTT 3.1.1 compatibility) and then
		// delivers nothing, so the receiver sees silence and ends with the context error, not a refusal.
		r := &Receiver{Connect: pubOpts, Topic: topic, Keys: iss.keys, MaxAge: 5 * time.Minute}
		if snap, err := r.Receive(ctxTimeout(t, 1500*time.Millisecond)); err == nil {
			t.Fatalf("the publisher account received %+v", snap)
		}
	})

	t.Run("wrong password is refused", func(t *testing.T) {
		bad := devOpts
		bad.Password = "nope"
		r := &Receiver{Connect: bad, Topic: topic, Keys: iss.keys, MaxAge: 5 * time.Minute}
		if _, err := r.Receive(ctxTimeout(t, 10*time.Second)); err == nil || !strings.Contains(err.Error(), "CONNACK code") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("a live update reaches a watcher and replaces the retained message", func(t *testing.T) {
		next := iss.snapshot(t, now.Add(2*time.Second), "dev-revoked-1", "dev-suspended-1", "dev-new")
		w := &Receiver{Connect: ConnectOptions{Addr: addr, ClientID: "theauth-test-watch", Username: "dev", Password: devOpts.Password}, Topic: topic, Keys: iss.keys, Owner: testOwner, MaxAge: 5 * time.Minute}
		ctx := ctxTimeout(t, 15*time.Second)
		counts := make(chan int, 4)
		go func() { _ = w.Watch(ctx, func(s *device.RevocationSnapshot) { counts <- s.Count }) }()
		if c := <-counts; c != 2 {
			t.Fatalf("first count %d, want 2", c)
		}
		if err := (&Publisher{Connect: pubOpts, Topic: topic}).Publish(ctx, next); err != nil {
			t.Fatal(err)
		}
		if c := <-counts; c != 3 {
			t.Fatalf("second count %d, want 3", c)
		}
	})
}
