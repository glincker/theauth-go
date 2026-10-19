package revocationmqtt

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// DefaultTopicPrefix is the topic root. The full topic is DefaultTopicPrefix plus the owner.
const DefaultTopicPrefix = "theauth/revocations/"

// maxSnapshotBytes bounds what Publish sends. A snapshot holds 8 bytes per listed device in base64,
// so 1 MiB is about 100,000 devices, far beyond what a constrained device can hold anyway.
const maxSnapshotBytes = 1 << 20

// TopicFor returns the topic for one owner: theauth/revocations/<owner>. The owner must be a single
// topic level, so a slash or wildcard is refused.
func TopicFor(owner string) (string, error) {
	if owner == "" || strings.ContainsAny(owner, "/+#\x00") {
		return "", errors.New("revocationmqtt: owner must be one non empty topic level without / + #")
	}
	return DefaultTopicPrefix + owner, nil
}

// Publisher publishes snapshots as retained messages.
type Publisher struct {
	Connect ConnectOptions
	// Topic is the topic name to publish on, for example from TopicFor. Wildcards are refused.
	Topic string
	// QoS is 0 or 1. The default 0 is replaced by 1 so a Publish that returns nil was acknowledged
	// by the broker; set AtMostOnce to opt out.
	QoS        byte
	AtMostOnce bool
}

// Publish connects, sends token as a retained message and disconnects. token is the compact JWS the
// server signed (typ device-revocations+jwt). The publisher does not verify it: it has no keys, and
// the receiving side verifies anyway. An empty token is refused because an empty retained message
// deletes the stored one on the broker (MQTT 3.1.1 section 3.3.1.3).
func (p *Publisher) Publish(ctx context.Context, token string) error {
	if !validTopicName(p.Topic) {
		return errors.New("revocationmqtt: Topic is empty or contains a wildcard")
	}
	if token == "" {
		return errors.New("revocationmqtt: refusing to publish an empty snapshot, it would clear the retained message")
	}
	if len(token) > maxSnapshotBytes {
		return fmt.Errorf("revocationmqtt: snapshot of %d bytes exceeds %d", len(token), maxSnapshotBytes)
	}
	qos := byte(1)
	if p.AtMostOnce {
		qos = 0
	} else if p.QoS == 1 {
		qos = 1
	}
	cl, err := dial(ctx, p.Connect)
	if err != nil {
		return err
	}
	defer cl.close()
	return cl.publish(p.Topic, []byte(token), true, qos)
}

// Run publishes the snapshot that source returns, now and then every interval, until ctx ends. A
// snapshot expires, so a publisher that stops leaves devices with a stale one: pick an interval well
// under the snapshot lifetime and the MaxAge your devices use. A failed source or publish is passed
// to onError (which may be nil) and retried at the next tick. Run returns ctx.Err().
func (p *Publisher) Run(ctx context.Context, source func(context.Context) (string, error), interval time.Duration, onError func(error)) error {
	if interval <= 0 {
		return errors.New("revocationmqtt: interval must be positive")
	}
	report := func(err error) {
		if err != nil && onError != nil {
			onError(err)
		}
	}
	once := func() {
		token, err := source(ctx)
		if err == nil {
			err = p.Publish(ctx, token)
		}
		report(err)
	}
	once()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			once()
		}
	}
}
