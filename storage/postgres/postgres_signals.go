package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/glincker/theauth-go/v2/signals"
	"github.com/jackc/pgx/v5"
)

// postgres_signals.go: signals.Store (Shared Signals Framework streams,
// subject filters and delivery queue) over migration 0026.

// SignalsStore returns a signals.Store backed by this database. Pass it as
// SharedSignalsConfig.Store.
func (s *Store) SignalsStore() signals.Store { return signalsStore{s} }

type signalsStore struct{ s *Store }

func sigErr(op string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("postgres: %s: %w", op, err)
}

func (g signalsStore) CreateStream(ctx context.Context, st signals.Stream) error {
	doc, err := json.Marshal(st)
	if err != nil {
		return sigErr("create signal stream", err)
	}
	created := st.CreatedAt
	if created.IsZero() {
		created = time.Now()
	}
	_, err = g.s.pool.Exec(ctx, `INSERT INTO signal_streams (id, receiver_id, doc, created_at) VALUES ($1,$2,$3,$4)`,
		st.ID, st.ReceiverID, string(doc), created)
	return sigErr("create signal stream", err)
}

func (g signalsStore) GetStream(ctx context.Context, id string) (signals.Stream, error) {
	var doc string
	err := g.s.pool.QueryRow(ctx, `SELECT doc FROM signal_streams WHERE id = $1`, id).Scan(&doc)
	if errors.Is(err, pgx.ErrNoRows) {
		return signals.Stream{}, signals.ErrNotFound
	}
	if err != nil {
		return signals.Stream{}, sigErr("get signal stream", err)
	}
	var st signals.Stream
	return st, sigErr("decode signal stream", json.Unmarshal([]byte(doc), &st))
}

func (g signalsStore) ListStreams(ctx context.Context, receiverID string) ([]signals.Stream, error) {
	rows, err := g.s.pool.Query(ctx, `SELECT doc FROM signal_streams WHERE ($1 = '' OR receiver_id = $1) ORDER BY created_at, id`, receiverID)
	if err != nil {
		return nil, sigErr("list signal streams", err)
	}
	defer rows.Close()
	var out []signals.Stream
	for rows.Next() {
		var doc string
		if err := rows.Scan(&doc); err != nil {
			return nil, sigErr("scan signal stream", err)
		}
		var st signals.Stream
		if err := json.Unmarshal([]byte(doc), &st); err != nil {
			return nil, sigErr("decode signal stream", err)
		}
		out = append(out, st)
	}
	return out, sigErr("list signal streams", rows.Err())
}

func (g signalsStore) UpdateStream(ctx context.Context, st signals.Stream) error {
	doc, err := json.Marshal(st)
	if err != nil {
		return sigErr("update signal stream", err)
	}
	tag, err := g.s.pool.Exec(ctx, `UPDATE signal_streams SET doc = $2 WHERE id = $1`, st.ID, string(doc))
	if err != nil {
		return sigErr("update signal stream", err)
	}
	if tag.RowsAffected() == 0 {
		return signals.ErrNotFound
	}
	_, err = g.s.pool.Exec(ctx, `UPDATE signal_queue SET push = $2 WHERE stream_id = $1`, st.ID, st.IsPush())
	return sigErr("retag signal queue", err)
}

func (g signalsStore) DeleteStream(ctx context.Context, id string) error {
	tx, err := g.s.pool.Begin(ctx)
	if err != nil {
		return sigErr("delete signal stream", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	for _, q := range []string{
		`DELETE FROM signal_queue WHERE stream_id = $1`,
		`DELETE FROM signal_subjects WHERE stream_id = $1`,
		`DELETE FROM signal_streams WHERE id = $1`,
	} {
		if _, err := tx.Exec(ctx, q, id); err != nil {
			return sigErr("delete signal stream", err)
		}
	}
	return sigErr("delete signal stream", tx.Commit(ctx))
}

func (g signalsStore) AddSubject(ctx context.Context, streamID, key string, subject []byte) error {
	_, err := g.s.pool.Exec(ctx, `INSERT INTO signal_subjects (stream_id, subject_key, subject) VALUES ($1,$2,$3)
ON CONFLICT (stream_id, subject_key) DO UPDATE SET subject = EXCLUDED.subject`, streamID, key, string(subject))
	return sigErr("add signal subject", err)
}

func (g signalsStore) RemoveSubject(ctx context.Context, streamID, key string) error {
	_, err := g.s.pool.Exec(ctx, `DELETE FROM signal_subjects WHERE stream_id = $1 AND subject_key = $2`, streamID, key)
	return sigErr("remove signal subject", err)
}

func (g signalsStore) HasSubject(ctx context.Context, streamID, key string) (bool, error) {
	var ok bool
	err := g.s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM signal_subjects WHERE stream_id = $1 AND subject_key = $2)`, streamID, key).Scan(&ok)
	return ok, sigErr("has signal subject", err)
}

func (g signalsStore) CountSubjects(ctx context.Context, streamID string) (int, error) {
	var n int
	err := g.s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM signal_subjects WHERE stream_id = $1`, streamID).Scan(&n)
	return n, sigErr("count signal subjects", err)
}

func (g signalsStore) Enqueue(ctx context.Context, p signals.PendingSET) error {
	created := p.CreatedAt
	if created.IsZero() {
		created = time.Now()
	}
	_, err := g.s.pool.Exec(ctx, `INSERT INTO signal_queue (id, stream_id, jti, token, push, attempts, next_at, created_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, p.ID, p.StreamID, p.JTI, p.Token, p.Push, p.Attempts, p.NextAt, created)
	return sigErr("enqueue signal", err)
}

const signalQueueCols = `id, stream_id, jti, token, push, attempts, next_at, created_at`

func (g signalsStore) queryQueue(ctx context.Context, q string, args ...any) ([]signals.PendingSET, error) {
	rows, err := g.s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, sigErr("query signal queue", err)
	}
	defer rows.Close()
	var out []signals.PendingSET
	for rows.Next() {
		var p signals.PendingSET
		if err := rows.Scan(&p.ID, &p.StreamID, &p.JTI, &p.Token, &p.Push, &p.Attempts, &p.NextAt, &p.CreatedAt); err != nil {
			return nil, sigErr("scan signal queue", err)
		}
		out = append(out, p)
	}
	return out, sigErr("query signal queue", rows.Err())
}

func (g signalsStore) DuePush(ctx context.Context, now time.Time, limit int) ([]signals.PendingSET, error) {
	return g.queryQueue(ctx, `SELECT `+signalQueueCols+` FROM signal_queue WHERE push AND next_at <= $1 ORDER BY created_at, id LIMIT $2`, now, limit)
}

func (g signalsStore) Pending(ctx context.Context, streamID string, limit int) ([]signals.PendingSET, error) {
	return g.queryQueue(ctx, `SELECT `+signalQueueCols+` FROM signal_queue WHERE stream_id = $1 ORDER BY created_at, id LIMIT $2`, streamID, limit)
}

func (g signalsStore) CountPending(ctx context.Context, streamID string) (int, error) {
	var n int
	err := g.s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM signal_queue WHERE stream_id = $1`, streamID).Scan(&n)
	return n, sigErr("count signal queue", err)
}

func (g signalsStore) MarkAttempt(ctx context.Context, id string, attempts int, next time.Time) error {
	_, err := g.s.pool.Exec(ctx, `UPDATE signal_queue SET attempts = $2, next_at = $3 WHERE id = $1`, id, attempts, next)
	return sigErr("mark signal attempt", err)
}

func (g signalsStore) Ack(ctx context.Context, streamID string, jtis []string) (int, error) {
	if len(jtis) == 0 {
		return 0, nil
	}
	tag, err := g.s.pool.Exec(ctx, `DELETE FROM signal_queue WHERE stream_id = $1 AND jti = ANY($2)`, streamID, jtis)
	if err != nil {
		return 0, sigErr("ack signals", err)
	}
	return int(tag.RowsAffected()), nil
}

func (g signalsStore) Drop(ctx context.Context, id string) error {
	_, err := g.s.pool.Exec(ctx, `DELETE FROM signal_queue WHERE id = $1`, id)
	return sigErr("drop signal", err)
}
