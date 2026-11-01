package postgres

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// DefaultPurgeChannel is the LISTEN and NOTIFY channel PurgeBroadcaster uses when none is set.
const DefaultPurgeChannel = "theauth_device_purge"

// purgeReconnectDelay is the pause before Subscribe listens again after a lost connection.
const purgeReconnectDelay = time.Second

// PurgeBroadcaster fans a device cache purge out to every replica over Postgres LISTEN and NOTIFY.
// It implements mqttauth.PurgeBroadcaster: pass it to Purger.SetBroadcaster and run Purger.Run on
// each replica. It needs no table and no migration.
//
// Publish sends one NOTIFY whose payload is the device ID, empty for "everything". The payload is
// not a secret and a ULID is far below the 8000 byte limit. NOTIFY is delivered to the listeners
// that are connected when the transaction commits, so a replica that was disconnected misses it.
// Subscribe therefore reports an empty ID (purge all) every time it has to reconnect, which
// covers the gap. Subscribe holds one connection of the pool for as long as it runs.
type PurgeBroadcaster struct {
	pool    *pgxpool.Pool
	channel string
}

// NewPurgeBroadcaster returns a broadcaster over pool. An empty channel means
// DefaultPurgeChannel. Use one channel per deployment: replicas of different environments that
// share a database must not share a channel.
func NewPurgeBroadcaster(pool *pgxpool.Pool, channel string) *PurgeBroadcaster {
	if channel == "" {
		channel = DefaultPurgeChannel
	}
	return &PurgeBroadcaster{pool: pool, channel: channel}
}

// Publish sends a purge for deviceID, or for everything when deviceID is empty.
func (b *PurgeBroadcaster) Publish(ctx context.Context, deviceID string) error {
	if _, err := b.pool.Exec(ctx, `SELECT pg_notify($1, $2)`, b.channel, deviceID); err != nil {
		return fmt.Errorf("postgres: publish purge: %w", err)
	}
	return nil
}

// Subscribe listens until ctx ends and returns nil then. A lost connection is retried forever
// after a short pause, and fn("") runs after each reconnect.
func (b *PurgeBroadcaster) Subscribe(ctx context.Context, fn func(deviceID string)) error {
	first := true
	for ctx.Err() == nil {
		err := b.listen(ctx, fn, !first)
		first = false
		if ctx.Err() != nil {
			return nil
		}
		slog.Warn("postgres: purge listener lost, reconnecting", "channel", b.channel, "err", fmt.Sprint(err))
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(purgeReconnectDelay):
		}
	}
	return nil
}

// listen holds one connection, LISTENs and relays notifications until it fails. afterGap says
// notifications may have been missed before this call.
func (b *PurgeBroadcaster) listen(ctx context.Context, fn func(string), afterGap bool) error {
	conn, err := b.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, "LISTEN "+pgx.Identifier{b.channel}.Sanitize()); err != nil {
		return err
	}
	if afterGap {
		fn("")
	}
	for {
		n, err := conn.Conn().WaitForNotification(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			// Drop the broken connection instead of returning it to the pool.
			_ = conn.Conn().Close(context.Background())
			return err
		}
		fn(n.Payload)
	}
}
