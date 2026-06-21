package admin_test

import (
	"testing"
	"time"

	"github.com/glincker/theauth-go/admin"
	"github.com/oklog/ulid/v2"
)

func TestCursorRoundTrip(t *testing.T) {
	cases := []struct {
		ts time.Time
		id ulid.ULID
	}{
		{time.Unix(0, 0), ulid.ULID{}},
		{time.Now().UTC().Truncate(time.Microsecond), ulid.Make()},
		{time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC), ulid.Make()},
	}
	for _, c := range cases {
		cursor := admin.EncodeCursor(c.ts, c.id)
		ts, id, err := admin.DecodeCursor(cursor)
		if err != nil {
			t.Fatalf("DecodeCursor(%q): %v", cursor, err)
		}
		if !ts.Equal(c.ts) {
			t.Errorf("ts mismatch: want=%v got=%v", c.ts, ts)
		}
		if id != c.id {
			t.Errorf("id mismatch: want=%v got=%v", c.id, id)
		}
	}
}

func TestCursorDecodeRejectsBadInput(t *testing.T) {
	for _, bad := range []string{
		"",
		"not-base64-!!",
		"YWJj",   // valid base64 but not "<int>:<ulid>"
		"MTIz",   // valid base64 of "123"
		"MTIzOg", // "123:" missing ULID
	} {
		if _, _, err := admin.DecodeCursor(bad); err == nil {
			t.Errorf("DecodeCursor(%q) should error", bad)
		}
	}
}

func FuzzCursorRoundTrip(f *testing.F) {
	f.Add(int64(0), uint64(0))
	f.Add(int64(1_700_000_000_000_000), uint64(42))
	f.Fuzz(func(t *testing.T, micros int64, seed uint64) {
		// Construct a ULID from the seed deterministically (avoid randomness in fuzz).
		var id ulid.ULID
		for i := 0; i < 16; i++ {
			id[i] = byte(seed >> (uint(i%8) * 8))
		}
		ts := time.UnixMicro(micros)
		cursor := admin.EncodeCursor(ts, id)
		ts2, id2, err := admin.DecodeCursor(cursor)
		if err != nil {
			t.Fatalf("DecodeCursor(%q): %v", cursor, err)
		}
		if !ts2.Equal(ts) {
			t.Errorf("ts mismatch: %v != %v", ts, ts2)
		}
		if id2 != id {
			t.Errorf("id mismatch: %x != %x", id, id2)
		}
	})
}
