package sqlite

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// as_common.go holds the small encoders shared by the authorization server
// storage files (as_*.go). List columns are JSON arrays in TEXT, the amr claim
// is a space separated list, and auth_time is Unix microseconds with NULL
// meaning the grant carried none.

func asEncodeList(v []string) (string, error) {
	if v == nil {
		v = []string{}
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("encode list: %w", err)
	}
	return string(b), nil
}

func asDecodeList(s string) ([]string, error) {
	out := []string{}
	if s == "" {
		return out, nil
	}
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return nil, fmt.Errorf("decode stored list %q: %w", s, err)
	}
	if out == nil {
		out = []string{}
	}
	return out, nil
}

func asDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func asAuthTimeArg(t time.Time) sql.NullInt64 {
	if t.IsZero() {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: toMicro(t), Valid: true}
}

func asAuthTimeFrom(n sql.NullInt64) time.Time {
	if !n.Valid {
		return time.Time{}
	}
	return fromMicro(n.Int64)
}

func asJoinAMR(amr []string) string { return strings.Join(amr, " ") }

func asSplitAMR(s string) []string { return strings.Fields(s) }
