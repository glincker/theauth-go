package fleet

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/glincker/theauth-go/v2/iot/device"
)

// ScenarioResult is the outcome of one scenario.
type ScenarioResult struct {
	Name string
	// Checks made across the fleet.
	Checks int
	// Failures are the first failures, at most 10, each naming the device index.
	Failures []string
}

// Report is the outcome of a run.
type Report struct {
	Devices   int
	Scenarios []ScenarioResult
	Passed    bool
}

const (
	allowedAction   = "publish"
	allowedResource = "mqtt:sensors:t1"
	deniedResource  = "mqtt:actuators:valve"
)

type checker struct {
	mu       sync.Mutex
	checks   int
	failures []string
}

func (c *checker) expect(ok bool, d *Device, format string, args ...any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.checks++
	if !ok && len(c.failures) < 10 {
		c.failures = append(c.failures, fmt.Sprintf("device %d: %s", d.Index, fmt.Sprintf(format, args...)))
	}
}

func (c *checker) result(name string) ScenarioResult {
	return ScenarioResult{Name: name, Checks: c.checks, Failures: c.failures}
}

// EnrollmentScenario: every device holds a distinct id after enrollment.
func (f *Fleet) EnrollmentScenario(_ context.Context) ScenarioResult {
	var c checker
	seen := map[string]bool{}
	for _, d := range f.Devices {
		c.expect(d.ID != "" && !seen[d.ID], d, "missing or duplicate device id")
		seen[d.ID] = true
	}
	return c.result("enrollment")
}

// AssertionScenario: the token endpoint gives a token for a granted scope and refuses an ungranted one
// with invalid_scope. This is the Go server's online decision (see the package comment).
func (f *Fleet) AssertionScenario(ctx context.Context) ScenarioResult {
	var c checker
	f.ForEach(ctx, func(d *Device) {
		var yes TokenResult
		var err error
		f.Latency.Time("token", func() { yes, err = d.Token(ctx, ScopeGranted) })
		c.expect(err == nil && yes.OK, d, "granted scope answered %d %s (%v)", yes.Status, yes.Error, err)
		no, err := d.Token(ctx, ScopeDenied)
		c.expect(err == nil && !no.OK && no.Error == "invalid_scope", d, "ungranted scope answered %d %s (%v)", no.Status, no.Error, err)
	})
	return c.result("assertion")
}

// BundleScenario: bundle and snapshot verify on the device, and the offline decision allows a granted
// action and denies an ungranted one.
func (f *Fleet) BundleScenario(ctx context.Context) ScenarioResult {
	var c checker
	f.ForEach(ctx, func(d *Device) {
		var status int
		var err error
		f.Latency.Time("fetchBundle", func() { status, err = d.FetchBundle(ctx) })
		c.expect(err == nil && status == 200, d, "bundle fetch answered %d (%v)", status, err)
		var verr error
		f.Latency.Time("verifyBundle", func() { _, verr = d.VerifyBundle(f.bundleTTL) })
		c.expect(verr == nil, d, "bundle did not verify: %v", verr)
		var yes OfflineDecision
		f.Latency.Time("decideOffline", func() { yes = d.DecideOffline(allowedAction, allowedResource, f.bundleTTL) })
		no := d.DecideOffline(allowedAction, deniedResource, f.bundleTTL)
		c.expect(yes.Verified && yes.Allowed, d, "offline allow differs from the server")
		c.expect(no.Verified && !no.Allowed, d, "offline deny differs from the server")
	})
	return c.result("bundle and snapshot")
}

// ClockSkewScenario: a device whose clock is off by minutes is refused, one inside the window is not.
func (f *Fleet) ClockSkewScenario(ctx context.Context, sample int) ScenarioResult {
	var c checker
	if sample <= 0 || sample > len(f.Devices) {
		sample = min(20, len(f.Devices))
	}
	for _, d := range f.Devices[:sample] {
		check := func(skew time.Duration, wantOK bool, label string) {
			d.SetSkew(skew)
			res, err := d.Token(ctx, ScopeGranted)
			c.expect(err == nil && res.OK == wantOK, d, "%s: answered %d %s (%v)", label, res.Status, res.Error, err)
		}
		check(10*time.Second, true, "10 s fast should be accepted")
		check(10*time.Minute, false, "10 min fast should be refused")
		check(-10*time.Minute, false, "10 min slow should be refused")
		check(-10*time.Second, true, "10 s slow should be accepted")
		d.SetSkew(0)
	}
	return c.result("clock skew")
}

// RollbackScenario: an older bundle presented after a newer one was accepted is refused.
func (f *Fleet) RollbackScenario(ctx context.Context, sample int) ScenarioResult {
	var c checker
	if sample <= 0 || sample > len(f.Devices) {
		sample = min(20, len(f.Devices))
	}
	for _, d := range f.Devices[:sample] {
		_, _ = d.FetchBundle(ctx)
		olderBundle, olderSnapshot := d.BundleToken, d.SnapshotToken
		f.Clock.Advance(2 * time.Second)
		_, _ = d.FetchBundle(ctx)
		_, err := d.VerifyBundle(f.bundleTTL)
		c.expect(err == nil, d, "fresh bundle did not verify: %v", err)
		d.BundleToken, d.SnapshotToken = olderBundle, olderSnapshot
		_, err = d.VerifyBundle(f.bundleTTL)
		var ve *device.VerifyError
		c.expect(errors.As(err, &ve) && ve.Reason == device.ReasonRollback, d, "an older bundle was accepted (%v)", err)
	}
	return c.result("rollback")
}

// OfflineScenario: offline use inside the bundle lifetime works, past it the device fails closed, back
// online it recovers.
func (f *Fleet) OfflineScenario(ctx context.Context) ScenarioResult {
	var c checker
	f.ForEach(ctx, func(d *Device) {
		_, _ = d.FetchBundle(ctx)
		_, _ = d.VerifyBundle(f.bundleTTL)
	})
	for _, d := range f.Devices {
		d.GoOffline()
	}
	f.ForEach(ctx, func(d *Device) {
		_, err := d.Token(ctx, ScopeGranted)
		c.expect(errors.Is(err, ErrOffline), d, "an offline device reached the server (%v)", err)
		within := d.DecideOffline(allowedAction, allowedResource, f.bundleTTL)
		c.expect(within.Verified && within.Allowed, d, "offline decision failed inside the lifetime")
	})
	f.Clock.Advance(f.bundleTTL + 2*time.Minute)
	f.ForEach(ctx, func(d *Device) {
		late := d.DecideOffline(allowedAction, allowedResource, f.bundleTTL)
		c.expect(!late.Allowed && !late.Verified, d, "an expired bundle still allowed an action")
	})
	for _, d := range f.Devices {
		d.GoOnline()
	}
	f.ForEach(ctx, func(d *Device) {
		_, _ = d.FetchBundle(ctx)
		back := d.DecideOffline(allowedAction, allowedResource, f.bundleTTL)
		c.expect(back.Verified && back.Allowed, d, "device did not recover after going online")
	})
	return c.result("offline and online")
}

// SuspendResumeScenario: a suspended device is refused tokens and bundles and is listed in the
// snapshot, and a resumed one works again.
func (f *Fleet) SuspendResumeScenario(ctx context.Context, sample int) ScenarioResult {
	var c checker
	if sample <= 0 || sample > len(f.Devices) {
		sample = min(5, len(f.Devices))
	}
	for _, d := range f.Devices[:sample] {
		if err := f.Suspend(ctx, d); err != nil {
			c.expect(false, d, "suspend: %v", err)
			continue
		}
		res, _ := d.Token(ctx, ScopeGranted)
		c.expect(!res.OK && res.Status >= 400 && res.Status < 500, d, "suspended device answered %d", res.Status)
		status, _ := d.FetchBundle(ctx)
		c.expect(status == 401, d, "suspended device still got a bundle (%d)", status)
		if err := f.Resume(ctx, d); err != nil {
			c.expect(false, d, "resume: %v", err)
			continue
		}
		res, _ = d.Token(ctx, ScopeGranted)
		c.expect(res.OK, d, "resumed device answered %d %s", res.Status, res.Error)
		status, _ = d.FetchBundle(ctx)
		c.expect(status == 200, d, "resumed device got no bundle (%d)", status)
	}
	return c.result("suspend and resume")
}

// RevocationScenario revokes devices in the middle of a session. The server stops them at once, and every
// other device that fetches a new snapshot learns of it. A device holding an old snapshot keeps its old view
// until the snapshot passes maxSnapshotAge, then fails closed. That window is the bound to document.
func (f *Fleet) RevocationScenario(ctx context.Context, revoke int, maxSnapshotAge time.Duration) ScenarioResult {
	var c checker
	if maxSnapshotAge <= 0 {
		maxSnapshotAge = f.bundleTTL
	}
	if revoke <= 0 {
		revoke = (len(f.Devices) + 99) / 100
	}
	revoke = max(1, min(revoke, len(f.Devices)-1))
	doomed, survivors := f.Devices[:revoke], f.Devices[revoke:]
	for _, d := range f.Devices {
		_, _ = d.FetchBundle(ctx)
		_, _ = d.VerifyBundle(maxSnapshotAge)
	}
	for _, d := range doomed {
		if err := f.Revoke(ctx, d); err != nil {
			c.expect(false, d, "revoke: %v", err)
		}
	}
	for _, d := range doomed {
		res, _ := d.Token(ctx, ScopeGranted)
		c.expect(!res.OK && res.Status >= 400 && res.Status < 500, d, "revoked device answered %d", res.Status)
		status, _ := d.FetchBundle(ctx)
		c.expect(status == 401, d, "revoked device still got a bundle (%d)", status)
	}
	stale := survivors[0]
	staleSnapshot := stale.SnapshotToken
	doomedSet := map[*Device]bool{}
	for _, d := range doomed {
		doomedSet[d] = true
	}
	f.ForEach(ctx, func(d *Device) {
		if doomedSet[d] {
			return
		}
		res, err := d.Token(ctx, ScopeGranted)
		c.expect(err == nil && res.OK, d, "a healthy device was affected by the revocation (%d %s)", res.Status, res.Error)
	})
	f.Clock.Advance(time.Second)
	_, _ = stale.FetchBundle(ctx)
	c.expect(stale.SnapshotToken != "" && stale.SnapshotToken != staleSnapshot, stale, "no new snapshot after revocation")
	snap, err := device.VerifyRevocations(device.RevocationOptions{Token: stale.SnapshotToken, MaxAge: maxSnapshotAge, Owner: f.OwnerID.String()},
		f.bundleKeys, device.DefaultIssuer, stale.Now())
	c.expect(err == nil, stale, "peer snapshot did not verify: %v", err)
	if err == nil {
		for _, d := range doomed {
			c.expect(snap.Contains(d.ID), d, "peer snapshot does not list a revoked device")
		}
		c.expect(!snap.Contains(stale.ID), stale, "peer snapshot lists a healthy device")
	}
	return c.result("revocation mid session")
}

// Run runs the whole kit in an order that leaves the revocation scenario last.
func (f *Fleet) Run(ctx context.Context) Report {
	scenarios := []ScenarioResult{
		f.EnrollmentScenario(ctx),
		f.AssertionScenario(ctx),
		f.BundleScenario(ctx),
		f.ClockSkewScenario(ctx, 0),
		f.RollbackScenario(ctx, 0),
		f.OfflineScenario(ctx),
		f.SuspendResumeScenario(ctx, 0),
		f.RevocationScenario(ctx, 0, f.bundleTTL),
	}
	passed := true
	for _, s := range scenarios {
		if len(s.Failures) > 0 {
			passed = false
		}
	}
	return Report{Devices: len(f.Devices), Scenarios: scenarios, Passed: passed}
}
