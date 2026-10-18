package mysql

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"time"
)

const (
	// DefaultPurgePollInterval is how often Subscribe looks for new purge rows.
	DefaultPurgePollInterval = 500 * time.Millisecond
	// DefaultPurgeRetention is how long a purge row is kept. It must be far above the poll
	// interval: a replica that was away longer than this misses rows, so it purges everything
	// when it comes back (see Subscribe).
	DefaultPurgeRetention = 10 * time.Minute

	purgeBatch      = 500
	purgePruneEvery = time.Minute
)

// PurgeBroadcaster fans a device cache purge out to every replica through a table, because MySQL
// has no LISTEN and NOTIFY. It implements mqttauth.PurgeBroadcaster: pass it to
// Purger.SetBroadcaster and run Purger.Run on each replica. It needs migration 0038
// (theauth_device_purge_events).
//
// Publish inserts one row (device ID, empty for "everything"). Subscribe polls for rows newer
// than a cursor, so latency is the poll interval, not CacheTTL. A subscriber starts at the
// current end of the table and never replays history. When a poll fails, the next poll that
// works reports fn("") (purge everything), since rows may have been pruned in between.
type PurgeBroadcaster struct {
	db        *sql.DB
	interval  time.Duration
	retention time.Duration
}

// NewPurgeBroadcaster returns a broadcaster over db. A zero interval or retention takes the
// default. Retention is raised to at least 20 poll intervals so a healthy replica never loses a
// row to pruning.
func NewPurgeBroadcaster(db *sql.DB, interval, retention time.Duration) *PurgeBroadcaster {
	if interval <= 0 {
		interval = DefaultPurgePollInterval
	}
	if retention <= 0 {
		retention = DefaultPurgeRetention
	}
	if retention < 20*interval {
		retention = 20 * interval
	}
	return &PurgeBroadcaster{db: db, interval: interval, retention: retention}
}

// Publish records a purge for deviceID, or for everything when deviceID is empty.
func (b *PurgeBroadcaster) Publish(ctx context.Context, deviceID string) error {
	if _, err := b.db.ExecContext(ctx, `INSERT INTO theauth_device_purge_events (device_id) VALUES (?)`, deviceID); err != nil {
		return fmt.Errorf("mysql: publish purge: %w", err)
	}
	return nil
}

// Subscribe polls until ctx ends and returns nil then. A failing database is retried on every
// tick forever, and fn("") runs after the first poll that works again.
func (b *PurgeBroadcaster) Subscribe(ctx context.Context, fn func(deviceID string)) error {
	cursor, err := b.tail(ctx)
	gap := err != nil
	if gap && ctx.Err() == nil {
		slog.Warn("mysql: purge subscriber could not read the table end", "err", fmt.Sprint(err))
	}
	tick := time.NewTicker(b.interval)
	defer tick.Stop()
	lastPrune := time.Now()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
		next, err := b.poll(ctx, cursor, gap, fn)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if !gap {
				slog.Warn("mysql: purge poll failed", "err", fmt.Sprint(err))
			}
			gap = true
			continue
		}
		cursor, gap = next, false
		if time.Since(lastPrune) >= purgePruneEvery {
			lastPrune = time.Now()
			b.prune(ctx)
		}
	}
}

// tail returns the highest id now in the table (0 when empty).
func (b *PurgeBroadcaster) tail(ctx context.Context) (int64, error) {
	var id sql.NullInt64
	if err := b.db.QueryRowContext(ctx, `SELECT MAX(id) FROM theauth_device_purge_events`).Scan(&id); err != nil {
		return 0, err
	}
	return id.Int64, nil
}

// poll delivers every row after cursor and returns the new cursor. afterGap runs fn("") first and
// skips to the table end, because rows missed during the gap are covered by the purge everything.
func (b *PurgeBroadcaster) poll(ctx context.Context, cursor int64, afterGap bool, fn func(string)) (int64, error) {
	if afterGap {
		end, err := b.tail(ctx)
		if err != nil {
			return cursor, err
		}
		fn("")
		return end, nil
	}
	for {
		rows, err := b.db.QueryContext(ctx,
			`SELECT id, device_id FROM theauth_device_purge_events WHERE id > ? ORDER BY id LIMIT ?`, cursor, purgeBatch)
		if err != nil {
			return cursor, err
		}
		type ev struct {
			id  int64
			dev string
		}
		var batch []ev
		for rows.Next() {
			var e ev
			if err := rows.Scan(&e.id, &e.dev); err != nil {
				_ = rows.Close()
				return cursor, err
			}
			batch = append(batch, e)
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return cursor, err
		}
		_ = rows.Close()
		for _, e := range batch {
			fn(e.dev)
			cursor = e.id
		}
		if len(batch) < purgeBatch {
			return cursor, nil
		}
	}
}

// prune deletes rows past the retention window. Every replica may run it, deleting is idempotent.
func (b *PurgeBroadcaster) prune(ctx context.Context) {
	secs := int64(b.retention / time.Second)
	if _, err := b.db.ExecContext(ctx,
		`DELETE FROM theauth_device_purge_events WHERE created_at < CURRENT_TIMESTAMP(6) - INTERVAL ? SECOND`, secs); err != nil && ctx.Err() == nil {
		slog.Warn("mysql: purge prune failed", "err", fmt.Sprint(err))
	}
}
