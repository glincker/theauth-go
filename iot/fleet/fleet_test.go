package fleet

import (
	"context"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2/iot/device"
)

func TestVirtualClock(t *testing.T) {
	c := NewVirtualClock(time.Time{})
	if !c.Now().Equal(DefaultStart) {
		t.Fatal("default start")
	}
	c.Advance(5 * time.Second)
	c.Advance(-time.Hour) // ignored: time only moves forward
	if !c.Now().Equal(DefaultStart.Add(5 * time.Second)) {
		t.Fatalf("now %v", c.Now())
	}
}

func TestPercentile(t *testing.T) {
	var v []time.Duration
	for i := 1; i <= 100; i++ {
		v = append(v, time.Duration(i)*time.Millisecond)
	}
	if Percentile(v, 50) != 50*time.Millisecond || Percentile(v, 99) != 99*time.Millisecond || Percentile(nil, 50) != 0 {
		t.Fatalf("p50 %v p99 %v", Percentile(v, 50), Percentile(v, 99))
	}
	s := Summarize(v)
	if s.Count != 100 || s.Max != 100*time.Millisecond {
		t.Fatalf("%+v", s)
	}
}

func TestSmallFleetPassesEveryScenario(t *testing.T) {
	ctx := context.Background()
	f, err := New(ctx, Options{Size: 30})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	report := f.Run(ctx)
	for _, s := range report.Scenarios {
		if len(s.Failures) > 0 {
			t.Errorf("%s: %v", s.Name, s.Failures)
		}
		if s.Checks == 0 {
			t.Errorf("%s made no checks", s.Name)
		}
	}
	if !report.Passed || len(report.Scenarios) != 8 {
		t.Fatalf("report: %+v", report)
	}
	if got := f.Latency.Report()["token"].Count; got < 30 {
		t.Fatalf("token calls: %d", got)
	}

	// A revoked device that keeps its old bundle but receives a peer's fresh snapshot refuses itself.
	revoked, peer := f.Devices[0], f.Devices[len(f.Devices)-1]
	if _, err := peer.FetchBundle(ctx); err != nil {
		t.Fatal(err)
	}
	revoked.SnapshotToken, revoked.LastSeq, revoked.LastSnapshotSeq = peer.SnapshotToken, 0, 0
	_, err = revoked.VerifyBundle(time.Hour)
	if ve, ok := err.(*device.VerifyError); !ok || ve.Reason != device.ReasonRevoked {
		t.Fatalf("want revoked, got %v", err)
	}
	// Flipping bytes of a bundle makes it invalid, never allowed.
	tok := peer.BundleToken
	peer.BundleToken = tok[:len(tok)-4] + "AAAA"
	if peer.DecideOffline(allowedAction, allowedResource, time.Hour).Allowed {
		t.Fatal("a tampered bundle allowed an action")
	}
}

func TestOfflineDeviceCannotReachTheServer(t *testing.T) {
	ctx := context.Background()
	f, err := New(ctx, Options{Size: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	d := f.Devices[0]
	d.GoOffline()
	if _, err := d.Token(ctx, ScopeGranted); err != ErrOffline {
		t.Fatalf("got %v", err)
	}
	if _, err := d.FetchBundle(ctx); err != ErrOffline {
		t.Fatalf("got %v", err)
	}
}
