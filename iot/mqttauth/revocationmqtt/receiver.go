package revocationmqtt

import (
	"context"
	"errors"
	"time"

	"github.com/glincker/theauth-go/v2/iot/device"
)

// Receiver subscribes to the snapshot topic and verifies what arrives.
type Receiver struct {
	Connect ConnectOptions
	// Topic is the exact topic the snapshot is published on (no wildcards), for example from TopicFor.
	Topic string
	// Keys verifies the snapshot signature: the same key set VerifyBundle uses (GET /device/jwks).
	Keys *device.KeySet
	// Issuer defaults to device.DefaultIssuer.
	Issuer string
	// Owner, when set, must equal the snapshot's owner. Set it to the owner of your bundle.
	Owner string
	// MaxAge fails a snapshot issued longer ago than this. Required, see device.RevocationOptions.
	MaxAge time.Duration
	// Now is the clock, default time.Now. A device without an RTC passes a SyncedClock reading.
	Now func() time.Time
	// LastSeq is the highest snapshot seq accepted before (persist it). Receive and Watch raise it
	// as they accept snapshots, and refuse a lower one as a rollback.
	LastSeq int64
	// OnError, when set, hears about rejected messages and reconnect failures in Watch.
	OnError func(error)
}

func (r *Receiver) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *Receiver) check() error {
	switch {
	case !validTopicName(r.Topic):
		return errors.New("revocationmqtt: Topic is empty or contains a wildcard")
	case r.Keys == nil:
		return errors.New("revocationmqtt: Keys is required")
	case r.MaxAge <= 0:
		return errors.New("revocationmqtt: MaxAge is required")
	}
	return nil
}

// verify checks one received message. A message on another topic is ignored (ok false, no error).
func (r *Receiver) verify(m message) (*device.RevocationSnapshot, bool, error) {
	if m.Topic != r.Topic {
		return nil, false, nil
	}
	issuer := r.Issuer
	if issuer == "" {
		issuer = device.DefaultIssuer
	}
	snap, err := device.VerifyRevocations(device.RevocationOptions{
		Token: string(m.Payload), MaxAge: r.MaxAge, Owner: r.Owner, LastSeq: r.LastSeq,
	}, r.Keys, issuer, r.now())
	if err != nil {
		return nil, true, err
	}
	return snap, true, nil
}

// Receive connects, subscribes and returns the first message that verifies, which is normally the
// retained snapshot delivered right after SUBACK. A message that fails verification is passed to
// OnError and skipped, so one bad or stale retained message does not end the wait. Receive returns
// ctx.Err() (wrapped with the last rejection, if any) when ctx ends first. It raises LastSeq.
func (r *Receiver) Receive(ctx context.Context) (*device.RevocationSnapshot, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	cl, err := dial(ctx, r.Connect)
	if err != nil {
		return nil, err
	}
	defer cl.close()
	early, err := cl.subscribe(r.Topic)
	if err != nil {
		return nil, err
	}
	var last error
	handle := func(m message) *device.RevocationSnapshot {
		snap, mine, verr := r.verify(m)
		if verr != nil {
			last = verr
			if r.OnError != nil {
				r.OnError(verr)
			}
		}
		if !mine || verr != nil {
			return nil
		}
		r.LastSeq = snap.Seq
		return snap
	}
	for _, m := range early {
		if snap := handle(m); snap != nil {
			return snap, nil
		}
	}
	for {
		m, err := cl.next(ctx)
		if err != nil {
			if last != nil && ctx.Err() != nil {
				return nil, errors.Join(err, last)
			}
			return nil, err
		}
		if snap := handle(m); snap != nil {
			return snap, nil
		}
	}
}

// Watch keeps a subscription open and calls fn for every snapshot that verifies and is newer than
// the last one (a retained message is delivered again after each reconnect, and is skipped when its
// seq was already seen). It reconnects with a backoff from one second up to one minute, and returns
// ctx.Err() when ctx ends. Until the first snapshot arrives, the device should keep failing closed.
func (r *Receiver) Watch(ctx context.Context, fn func(*device.RevocationSnapshot)) error {
	if err := r.check(); err != nil {
		return err
	}
	backoff := time.Second
	for ctx.Err() == nil {
		got, err := r.watchOnce(ctx, fn)
		if err != nil && ctx.Err() == nil && r.OnError != nil {
			r.OnError(err)
		}
		if got {
			backoff = time.Second
		}
		select {
		case <-ctx.Done():
		case <-time.After(backoff):
		}
		if backoff < time.Minute {
			backoff *= 2
		}
	}
	return ctx.Err()
}

// watchOnce runs one connection. got reports whether it delivered a snapshot (to reset the backoff).
func (r *Receiver) watchOnce(ctx context.Context, fn func(*device.RevocationSnapshot)) (got bool, err error) {
	cl, err := dial(ctx, r.Connect)
	if err != nil {
		return false, err
	}
	defer cl.close()
	early, err := cl.subscribe(r.Topic)
	if err != nil {
		return false, err
	}
	deliver := func(m message) {
		prev := r.LastSeq
		snap, mine, verr := r.verify(m)
		switch {
		case verr != nil:
			// An equal seq is a redelivery of the retained message, not a problem worth reporting.
			if r.OnError != nil && prev == r.LastSeq {
				r.OnError(verr)
			}
		case mine && snap.Seq > prev:
			r.LastSeq = snap.Seq
			got = true
			fn(snap)
		}
	}
	for _, m := range early {
		deliver(m)
	}
	for {
		m, err := cl.next(ctx)
		if err != nil {
			return got, err
		}
		deliver(m)
	}
}
