package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/glincker/theauth-go/v2/signals"
)

// signals.go: signals.Store (Shared Signals Framework streams, subject
// filters and delivery queue) over migration 0012.

// SignalsStore returns a signals.Store backed by this database. Pass it as
// SharedSignalsConfig.Store.
func (s *Store) SignalsStore() signals.Store { return signalsStore{s} }

type signalsStore struct{ s *Store }

func (g signalsStore) CreateStream(ctx context.Context, st signals.Stream) error {
	doc, err := json.Marshal(st)
	if err != nil {
		return wrap("create signal stream", err)
	}
	_, err = g.s.db.ExecContext(ctx, g.s.q(`INSERT INTO theauth_signal_streams (id, receiver_id, doc, created_at) VALUES (?, ?, ?, ?)`),
		st.ID, st.ReceiverID, string(doc), toMicro(orNow(st.CreatedAt)))
	return wrap("create signal stream", err)
}

func (g signalsStore) GetStream(ctx context.Context, id string) (signals.Stream, error) {
	var doc string
	err := g.s.db.QueryRowContext(ctx, g.s.q(`SELECT doc FROM theauth_signal_streams WHERE id = ?`), id).Scan(&doc)
	if errors.Is(err, sql.ErrNoRows) {
		return signals.Stream{}, signals.ErrNotFound
	}
	if err != nil {
		return signals.Stream{}, wrap("get signal stream", err)
	}
	var st signals.Stream
	return st, wrap("decode signal stream", json.Unmarshal([]byte(doc), &st))
}

func (g signalsStore) ListStreams(ctx context.Context, receiverID string) ([]signals.Stream, error) {
	q := `SELECT doc FROM theauth_signal_streams`
	var args []any
	if receiverID != "" {
		q += ` WHERE receiver_id = ?`
		args = append(args, receiverID)
	}
	rows, err := g.s.db.QueryContext(ctx, g.s.q(q+` ORDER BY created_at, id`), args...)
	if err != nil {
		return nil, wrap("list signal streams", err)
	}
	defer func() { _ = rows.Close() }()
	var out []signals.Stream
	for rows.Next() {
		var doc string
		if err := rows.Scan(&doc); err != nil {
			return nil, wrap("scan signal stream", err)
		}
		var st signals.Stream
		if err := json.Unmarshal([]byte(doc), &st); err != nil {
			return nil, wrap("decode signal stream", err)
		}
		out = append(out, st)
	}
	return out, wrap("list signal streams", rows.Err())
}

func (g signalsStore) UpdateStream(ctx context.Context, st signals.Stream) error {
	doc, err := json.Marshal(st)
	if err != nil {
		return wrap("update signal stream", err)
	}
	res, err := g.s.db.ExecContext(ctx, g.s.q(`UPDATE theauth_signal_streams SET doc = ? WHERE id = ?`), string(doc), st.ID)
	if err != nil {
		return wrap("update signal stream", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return signals.ErrNotFound
	}
	push := 0
	if st.IsPush() {
		push = 1
	}
	_, err = g.s.db.ExecContext(ctx, g.s.q(`UPDATE theauth_signal_queue SET push = ? WHERE stream_id = ?`), push, st.ID)
	return wrap("retag signal queue", err)
}

func (g signalsStore) DeleteStream(ctx context.Context, id string) error {
	for _, q := range []string{
		`DELETE FROM theauth_signal_queue WHERE stream_id = ?`,
		`DELETE FROM theauth_signal_subjects WHERE stream_id = ?`,
		`DELETE FROM theauth_signal_streams WHERE id = ?`,
	} {
		if _, err := g.s.db.ExecContext(ctx, g.s.q(q), id); err != nil {
			return wrap("delete signal stream", err)
		}
	}
	return nil
}

func (g signalsStore) AddSubject(ctx context.Context, streamID, key string, subject []byte) error {
	_, err := g.s.db.ExecContext(ctx, g.s.q(`INSERT INTO theauth_signal_subjects (stream_id, subject_key, subject) VALUES (?, ?, ?)
ON CONFLICT (stream_id, subject_key) DO UPDATE SET subject = excluded.subject`), streamID, key, string(subject))
	return wrap("add signal subject", err)
}

func (g signalsStore) RemoveSubject(ctx context.Context, streamID, key string) error {
	_, err := g.s.db.ExecContext(ctx, g.s.q(`DELETE FROM theauth_signal_subjects WHERE stream_id = ? AND subject_key = ?`), streamID, key)
	return wrap("remove signal subject", err)
}

func (g signalsStore) HasSubject(ctx context.Context, streamID, key string) (bool, error) {
	var one int
	err := g.s.db.QueryRowContext(ctx, g.s.q(`SELECT 1 FROM theauth_signal_subjects WHERE stream_id = ? AND subject_key = ?`), streamID, key).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, wrap("has signal subject", err)
}

func (g signalsStore) CountSubjects(ctx context.Context, streamID string) (int, error) {
	var n int
	err := g.s.db.QueryRowContext(ctx, g.s.q(`SELECT COUNT(*) FROM theauth_signal_subjects WHERE stream_id = ?`), streamID).Scan(&n)
	return n, wrap("count signal subjects", err)
}

func (g signalsStore) Enqueue(ctx context.Context, p signals.PendingSET) error {
	push := 0
	if p.Push {
		push = 1
	}
	_, err := g.s.db.ExecContext(ctx, g.s.q(`INSERT INTO theauth_signal_queue (id, stream_id, jti, token, push, attempts, next_at, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)`), p.ID, p.StreamID, p.JTI, p.Token, push, p.Attempts, toMicro(p.NextAt), toMicro(orNow(p.CreatedAt)))
	return wrap("enqueue signal", err)
}

const signalQueueCols = `id, stream_id, jti, token, push, attempts, next_at, created_at`

func (g signalsStore) queryQueue(ctx context.Context, q string, args ...any) ([]signals.PendingSET, error) {
	rows, err := g.s.db.QueryContext(ctx, g.s.q(q), args...)
	if err != nil {
		return nil, wrap("query signal queue", err)
	}
	defer func() { _ = rows.Close() }()
	var out []signals.PendingSET
	for rows.Next() {
		var p signals.PendingSET
		var push int
		var next, created int64
		if err := rows.Scan(&p.ID, &p.StreamID, &p.JTI, &p.Token, &push, &p.Attempts, &next, &created); err != nil {
			return nil, wrap("scan signal queue", err)
		}
		p.Push, p.NextAt, p.CreatedAt = push != 0, fromMicro(next), fromMicro(created)
		out = append(out, p)
	}
	return out, wrap("query signal queue", rows.Err())
}

func (g signalsStore) DuePush(ctx context.Context, now time.Time, limit int) ([]signals.PendingSET, error) {
	return g.queryQueue(ctx, `SELECT `+signalQueueCols+` FROM theauth_signal_queue WHERE push = 1 AND next_at <= ?
ORDER BY created_at, id LIMIT ?`, toMicro(now), limit)
}

func (g signalsStore) Pending(ctx context.Context, streamID string, limit int) ([]signals.PendingSET, error) {
	return g.queryQueue(ctx, `SELECT `+signalQueueCols+` FROM theauth_signal_queue WHERE stream_id = ?
ORDER BY created_at, id LIMIT ?`, streamID, limit)
}

func (g signalsStore) CountPending(ctx context.Context, streamID string) (int, error) {
	var n int
	err := g.s.db.QueryRowContext(ctx, g.s.q(`SELECT COUNT(*) FROM theauth_signal_queue WHERE stream_id = ?`), streamID).Scan(&n)
	return n, wrap("count signal queue", err)
}

func (g signalsStore) MarkAttempt(ctx context.Context, id string, attempts int, next time.Time) error {
	_, err := g.s.db.ExecContext(ctx, g.s.q(`UPDATE theauth_signal_queue SET attempts = ?, next_at = ? WHERE id = ?`), attempts, toMicro(next), id)
	return wrap("mark signal attempt", err)
}

func (g signalsStore) Ack(ctx context.Context, streamID string, jtis []string) (int, error) {
	if len(jtis) == 0 {
		return 0, nil
	}
	marks := strings.TrimSuffix(strings.Repeat("?,", len(jtis)), ",")
	args := make([]any, 0, len(jtis)+1)
	args = append(args, streamID)
	for _, j := range jtis {
		args = append(args, j)
	}
	res, err := g.s.db.ExecContext(ctx, g.s.q(`DELETE FROM theauth_signal_queue WHERE stream_id = ? AND jti IN (`+marks+`)`), args...)
	if err != nil {
		return 0, wrap("ack signals", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

func (g signalsStore) Drop(ctx context.Context, id string) error {
	_, err := g.s.db.ExecContext(ctx, g.s.q(`DELETE FROM theauth_signal_queue WHERE id = ?`), id)
	return wrap("drop signal", err)
}
