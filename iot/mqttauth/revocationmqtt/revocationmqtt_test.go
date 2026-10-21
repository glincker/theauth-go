package revocationmqtt

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2/iot/device"
)

const testOwner = "owner-1"

type issuer struct {
	signer *device.Signer
	keys   *device.KeySet
}

func newIssuer(t *testing.T) issuer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := device.NewSigner(priv, nil)
	if err != nil {
		t.Fatal(err)
	}
	pub := s.Public()
	pub.KID = "rev-key"
	return issuer{signer: s, keys: device.NewKeySet(pub)}
}

func (i issuer) snapshot(t *testing.T, iat time.Time, ids ...string) string {
	t.Helper()
	tok, err := i.signer.SignRevocations("rev-key", device.DefaultIssuer, testOwner, ids, iat, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func ctxTimeout(t *testing.T, d time.Duration) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}

func TestTopicFor(t *testing.T) {
	if got, err := TopicFor("owner-1"); err != nil || got != "theauth/revocations/owner-1" {
		t.Fatalf("TopicFor = %q, %v", got, err)
	}
	for _, bad := range []string{"", "a/b", "a+", "#", "x\x00y"} {
		if _, err := TopicFor(bad); err == nil {
			t.Errorf("TopicFor(%q) succeeded", bad)
		}
	}
}

func TestPublishIsRetainedAndReceivedAfterTheFact(t *testing.T) {
	b := newFakeBroker(t)
	iss := newIssuer(t)
	topic, _ := TopicFor(testOwner)
	now := time.Now()
	tok := iss.snapshot(t, now, "dev-revoked-1", "dev-suspended-1")

	pub := &Publisher{Connect: ConnectOptions{Addr: b.addr()}, Topic: topic}
	if err := pub.Publish(ctxTimeout(t, 5*time.Second), tok); err != nil {
		t.Fatal(err)
	}
	m, ok := b.retainedFor(topic)
	if !ok || !m.Retain || m.QoS != 1 || string(m.Payload) != tok {
		t.Fatalf("broker holds %+v, want the token retained at QoS 1", m)
	}

	// The device connects after the publisher is long gone and still gets the snapshot.
	rcv := &Receiver{
		Connect: ConnectOptions{Addr: b.addr(), ClientID: "dev-1"}, Topic: topic, Keys: iss.keys,
		Owner: testOwner, MaxAge: 5 * time.Minute,
	}
	snap, err := rcv.Receive(ctxTimeout(t, 5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if snap.Count != 2 || !snap.Contains("dev-revoked-1") || !snap.Contains("dev-suspended-1") || snap.Contains("dev-1") {
		t.Fatalf("unexpected snapshot: count %d", snap.Count)
	}
	if rcv.LastSeq != snap.Seq || snap.Seq == 0 {
		t.Errorf("LastSeq %d, snapshot seq %d", rcv.LastSeq, snap.Seq)
	}
}

func TestPublishRefusals(t *testing.T) {
	b := newFakeBroker(t)
	ctx := ctxTimeout(t, 5*time.Second)
	good := &Publisher{Connect: ConnectOptions{Addr: b.addr()}, Topic: "theauth/revocations/o"}
	if err := good.Publish(ctx, ""); err == nil {
		t.Error("an empty snapshot was published (it would clear the retained message)")
	}
	if err := good.Publish(ctx, strings.Repeat("a", maxSnapshotBytes+1)); err == nil {
		t.Error("an oversized snapshot was published")
	}
	for _, topic := range []string{"", "theauth/+/o", "theauth/#"} {
		p := &Publisher{Connect: ConnectOptions{Addr: b.addr()}, Topic: topic}
		if err := p.Publish(ctx, "tok"); err == nil {
			t.Errorf("topic %q accepted", topic)
		}
	}
	if n := len(b.publishedMsgs()); n != 0 {
		t.Errorf("%d messages reached the broker, want 0", n)
	}
}

func TestPublisherAtMostOnce(t *testing.T) {
	b := newFakeBroker(t)
	p := &Publisher{Connect: ConnectOptions{Addr: b.addr()}, Topic: "t/x", AtMostOnce: true}
	if err := p.Publish(ctxTimeout(t, 5*time.Second), "tok"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for len(b.publishedMsgs()) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if m := b.publishedMsgs(); len(m) != 1 || m[0].QoS != 0 || !m[0].Retain {
		t.Fatalf("published %+v", m)
	}
}

func TestReceiveRejectsForgedStaleAndForeignSnapshots(t *testing.T) {
	iss := newIssuer(t)
	other := newIssuer(t)
	topic, _ := TopicFor(testOwner)
	now := time.Now()
	cases := []struct {
		name  string
		token string
	}{
		{"signed by a key we do not trust", other.snapshot(t, now, "dev-1")},
		{"older than MaxAge", iss.snapshot(t, now.Add(-30*time.Minute), "dev-1")},
		{"not a snapshot", "garbage"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := newFakeBroker(t)
			if err := (&Publisher{Connect: ConnectOptions{Addr: b.addr()}, Topic: topic}).Publish(ctxTimeout(t, 5*time.Second), c.token); err != nil {
				t.Fatal(err)
			}
			var rejected []error
			rcv := &Receiver{
				Connect: ConnectOptions{Addr: b.addr()}, Topic: topic, Keys: iss.keys, Owner: testOwner,
				MaxAge: 5 * time.Minute, OnError: func(err error) { rejected = append(rejected, err) },
			}
			ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
			defer cancel()
			if snap, err := rcv.Receive(ctx); err == nil {
				t.Fatalf("accepted %+v", snap)
			}
			if len(rejected) == 0 {
				t.Error("the rejection was not reported")
			}
			if rcv.LastSeq != 0 {
				t.Errorf("LastSeq moved to %d", rcv.LastSeq)
			}
		})
	}

	t.Run("another owner", func(t *testing.T) {
		b := newFakeBroker(t)
		tok, _ := iss.signer.SignRevocations("rev-key", device.DefaultIssuer, "owner-2", nil, now, time.Hour)
		_ = (&Publisher{Connect: ConnectOptions{Addr: b.addr()}, Topic: topic}).Publish(ctxTimeout(t, 5*time.Second), tok)
		rcv := &Receiver{Connect: ConnectOptions{Addr: b.addr()}, Topic: topic, Keys: iss.keys, Owner: testOwner, MaxAge: 5 * time.Minute}
		ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
		defer cancel()
		if _, err := rcv.Receive(ctx); err == nil {
			t.Fatal("a snapshot for another owner was accepted")
		}
	})

	t.Run("rollback below LastSeq", func(t *testing.T) {
		b := newFakeBroker(t)
		old := iss.snapshot(t, now.Add(-time.Minute), "dev-1")
		_ = (&Publisher{Connect: ConnectOptions{Addr: b.addr()}, Topic: topic}).Publish(ctxTimeout(t, 5*time.Second), old)
		rcv := &Receiver{
			Connect: ConnectOptions{Addr: b.addr()}, Topic: topic, Keys: iss.keys, Owner: testOwner,
			MaxAge: 5 * time.Minute, LastSeq: now.UnixMilli(),
		}
		ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
		defer cancel()
		if _, err := rcv.Receive(ctx); err == nil {
			t.Fatal("an older snapshot than LastSeq was accepted")
		}
	})
}

func TestReceiveNeedsKeysMaxAgeAndAnExactTopic(t *testing.T) {
	iss := newIssuer(t)
	base := Receiver{Connect: ConnectOptions{Addr: "127.0.0.1:1"}, Topic: "t/x", Keys: iss.keys, MaxAge: time.Minute}
	for name, mut := range map[string]func(*Receiver){
		"no keys":     func(r *Receiver) { r.Keys = nil },
		"no max age":  func(r *Receiver) { r.MaxAge = 0 },
		"wildcard":    func(r *Receiver) { r.Topic = "theauth/revocations/#" },
		"empty topic": func(r *Receiver) { r.Topic = "" },
	} {
		r := base
		mut(&r)
		if _, err := r.Receive(ctxTimeout(t, time.Second)); err == nil || strings.Contains(err.Error(), "dial") {
			t.Errorf("%s: err = %v, want a configuration error before dialing", name, err)
		}
	}
}

func TestReceiveReportsBrokerRefusals(t *testing.T) {
	iss := newIssuer(t)
	rcv := func(addr string) *Receiver {
		return &Receiver{Connect: ConnectOptions{Addr: addr, Username: "dev", Password: "pw"}, Topic: "t/x", Keys: iss.keys, MaxAge: time.Minute}
	}
	t.Run("bad credentials", func(t *testing.T) {
		b := newFakeBroker(t)
		b.user = "someone-else"
		if _, err := rcv(b.addr()).Receive(ctxTimeout(t, 3*time.Second)); err == nil || !strings.Contains(err.Error(), "CONNACK code 5") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("subscribe denied by the topic ACL", func(t *testing.T) {
		b := newFakeBroker(t)
		b.denySub = true
		if _, err := rcv(b.addr()).Receive(ctxTimeout(t, 3*time.Second)); err == nil || !strings.Contains(err.Error(), "refused the subscription") {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestWatchDeliversOnlyNewerSnapshotsAndSurvivesReconnect(t *testing.T) {
	b := newFakeBroker(t)
	iss := newIssuer(t)
	topic, _ := TopicFor(testOwner)
	pub := &Publisher{Connect: ConnectOptions{Addr: b.addr()}, Topic: topic}
	now := time.Now()
	if err := pub.Publish(ctxTimeout(t, 5*time.Second), iss.snapshot(t, now.Add(-2*time.Second), "dev-a")); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var seen []int
	got := make(chan struct{}, 8)
	rcv := &Receiver{Connect: ConnectOptions{Addr: b.addr(), KeepAlive: 2 * time.Second}, Topic: topic, Keys: iss.keys, Owner: testOwner, MaxAge: 5 * time.Minute}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- rcv.Watch(ctx, func(s *device.RevocationSnapshot) {
			mu.Lock()
			seen = append(seen, s.Count)
			mu.Unlock()
			got <- struct{}{}
		})
	}()
	wait := func() {
		t.Helper()
		select {
		case <-got:
		case <-time.After(5 * time.Second):
			t.Fatal("no snapshot delivered")
		}
	}
	wait() // the retained one

	// A live update with a higher seq, then a replay of the first (a rollback) that must be ignored.
	if err := pub.Publish(ctxTimeout(t, 5*time.Second), iss.snapshot(t, now, "dev-a", "dev-b")); err != nil {
		t.Fatal(err)
	}
	wait()
	if err := pub.Publish(ctxTimeout(t, 5*time.Second), iss.snapshot(t, now.Add(-time.Second), "dev-a")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-got:
		t.Fatal("an older snapshot was delivered after a newer one")
	case <-time.After(300 * time.Millisecond):
	}

	cancel()
	if err := <-done; err != context.Canceled {
		t.Fatalf("Watch returned %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 2 || seen[0] != 1 || seen[1] != 2 {
		t.Fatalf("delivered counts %v, want [1 2]", seen)
	}
}

func TestRunRepublishesAndReportsErrors(t *testing.T) {
	b := newFakeBroker(t)
	iss := newIssuer(t)
	p := &Publisher{Connect: ConnectOptions{Addr: b.addr()}, Topic: "theauth/revocations/o"}
	var mu sync.Mutex
	calls := 0
	var errs []error
	ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
	defer cancel()
	err := p.Run(ctx, func(context.Context) (string, error) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if calls == 2 {
			return "", os.ErrDeadlineExceeded
		}
		return iss.snapshot(t, time.Now()), nil
	}, 250*time.Millisecond, func(err error) {
		mu.Lock()
		errs = append(errs, err)
		mu.Unlock()
	})
	if err != context.DeadlineExceeded {
		t.Fatalf("Run returned %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if calls < 3 || len(errs) != 1 {
		t.Errorf("source called %d times with %d reported errors, want at least 3 and exactly 1", calls, len(errs))
	}
	if got := len(b.publishedMsgs()); got != calls-1 {
		t.Errorf("%d messages published for %d source calls", got, calls)
	}
	if err := p.Run(context.Background(), nil, 0, nil); err == nil {
		t.Error("a zero interval was accepted")
	}
}

// TestTypeScriptSignedSnapshotOverMQTT sends a snapshot signed by the TypeScript issuer (from the
// shared vectors) through the broker and verifies it with the vector JWKS.
func TestTypeScriptSignedSnapshotOverMQTT(t *testing.T) {
	raw, err := os.ReadFile("../../device/testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		JWKS      json.RawMessage `json:"jwks"`
		Snapshots []struct {
			Token         string `json:"token"`
			Owner         string `json:"owner"`
			MaxAgeSeconds int64  `json:"maxAgeSeconds"`
			Now           int64  `json:"now"`
		} `json:"snapshots"`
	}
	if err := json.Unmarshal(raw, &v); err != nil || len(v.Snapshots) == 0 {
		t.Fatalf("vectors: %v", err)
	}
	keys, err := device.ParseJWKS(v.JWKS)
	if err != nil {
		t.Fatal(err)
	}
	s := v.Snapshots[0]
	b := newFakeBroker(t)
	topic, _ := TopicFor(s.Owner)
	if err := (&Publisher{Connect: ConnectOptions{Addr: b.addr()}, Topic: topic}).Publish(ctxTimeout(t, 5*time.Second), s.Token); err != nil {
		t.Fatal(err)
	}
	rcv := &Receiver{
		Connect: ConnectOptions{Addr: b.addr()}, Topic: topic, Keys: keys, Owner: s.Owner,
		MaxAge: time.Duration(s.MaxAgeSeconds) * time.Second, Now: func() time.Time { return time.Unix(s.Now, 0) },
	}
	snap, err := rcv.Receive(ctxTimeout(t, 5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if snap.Count != 3 || !snap.Contains("dev-revoked-1") || snap.Contains("dev-1") {
		t.Fatalf("count %d", snap.Count)
	}
}
