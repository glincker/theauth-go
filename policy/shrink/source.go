package shrink

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// DefaultPageSize is the rows read per query when none is set.
const DefaultPageSize = 1000

// RowQuery asks a RowSource for one page of an agent's decision rows.
type RowQuery struct {
	AgentID string
	// Since and Until bound the window, inclusive. A zero time is unbounded.
	Since time.Time
	Until time.Time
	// After is the opaque cursor returned with the previous page. Empty starts
	// from the beginning.
	After string
	// Limit is the most rows to return. A source may return fewer.
	Limit int
}

// RowSource pages through an agent's decision rows. It owns the cursor, so a
// store can use whatever keyset it has. next is empty on the last page. A page
// may be short or empty while next is non-empty (a source that filters after
// reading); callers keep going until next is empty.
type RowSource interface {
	Rows(ctx context.Context, q RowQuery) (rows []DecisionRow, next string, err error)
}

// GrantSource returns the agent's effective permissions at now, one action per
// grant: own grants first, then delegated ones that are active and unexpired.
// Order matters: attribution is first match, like the engine.
type GrantSource interface {
	Grants(ctx context.Context, agentID string, now time.Time) ([]Grant, error)
}

// ErrCursorStuck is returned when a RowSource hands back the cursor it was
// given, which would loop forever.
var ErrCursorStuck = errors.New("shrink: row source returned the same cursor")

func pageSize(n int) int {
	if n <= 0 {
		return DefaultPageSize
	}
	return n
}

// walk reads every page of q and calls fn for each row. Memory use is one page.
func walk(ctx context.Context, src RowSource, q RowQuery, size int, fn func(DecisionRow)) error {
	q.Limit = pageSize(size)
	for {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("shrink: read rows for agent %s: %w", q.AgentID, err)
		}
		rows, next, err := src.Rows(ctx, q)
		if err != nil {
			return fmt.Errorf("shrink: read rows for agent %s: %w", q.AgentID, err)
		}
		for _, r := range rows {
			fn(r)
		}
		if next == "" {
			return nil
		}
		if next == q.After {
			return fmt.Errorf("shrink: read rows for agent %s: %w", q.AgentID, ErrCursorStuck)
		}
		q.After = next
	}
}

// MemoryRows is an in-memory RowSource over a fixed set of rows. It pages
// oldest first with a (timestamp, id) keyset cursor, so rows that share a
// timestamp are never skipped or repeated. Useful for tests, exports and demos.
// AgentID on the query is ignored: the rows are taken to belong to the agent.
type MemoryRows []DecisionRow

// Rows implements RowSource.
func (m MemoryRows) Rows(_ context.Context, q RowQuery) ([]DecisionRow, string, error) {
	sorted := make([]DecisionRow, len(m))
	copy(sorted, m)
	sort.SliceStable(sorted, func(i, j int) bool { return before(sorted[i], sorted[j]) })

	var afterTS time.Time
	var afterID string
	if q.After != "" {
		ts, id, err := decodeCursor(q.After)
		if err != nil {
			return nil, "", err
		}
		afterTS, afterID = ts, id
	}
	limit := pageSize(q.Limit)
	var out []DecisionRow
	for _, r := range sorted {
		if !q.Since.IsZero() && r.Timestamp.Before(q.Since) {
			continue
		}
		if !q.Until.IsZero() && r.Timestamp.After(q.Until) {
			continue
		}
		if q.After != "" && !after(r, afterTS, afterID) {
			continue
		}
		out = append(out, r)
		if len(out) == limit {
			break
		}
	}
	if len(out) < limit {
		return out, "", nil
	}
	last := out[len(out)-1]
	// A full page may be the last one; the next call returns empty and ends.
	return out, encodeCursor(last.Timestamp, last.ID), nil
}

func before(a, b DecisionRow) bool {
	if !a.Timestamp.Equal(b.Timestamp) {
		return a.Timestamp.Before(b.Timestamp)
	}
	return a.ID < b.ID
}

func after(r DecisionRow, ts time.Time, id string) bool {
	if !r.Timestamp.Equal(ts) {
		return r.Timestamp.After(ts)
	}
	return r.ID > id
}

func encodeCursor(ts time.Time, id string) string {
	return strconv.FormatInt(ts.UnixNano(), 10) + ":" + id
}

func decodeCursor(s string) (time.Time, string, error) {
	n, id, ok := strings.Cut(s, ":")
	if !ok {
		return time.Time{}, "", errors.New("shrink: malformed row cursor")
	}
	ns, err := strconv.ParseInt(n, 10, 64)
	if err != nil {
		return time.Time{}, "", fmt.Errorf("shrink: malformed row cursor: %w", err)
	}
	return time.Unix(0, ns), id, nil
}
