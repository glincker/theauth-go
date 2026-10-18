package audit

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/glincker/theauth-go/v2/internal/models"
	"github.com/oklog/ulid/v2"
)

func TestCursorRoundTrip(t *testing.T) {
	t.Parallel()
	id := ulid.Make()
	for _, order := range []string{models.AuditOrderAsc, models.AuditOrderDesc} {
		order := order
		t.Run(order, func(t *testing.T) {
			t.Parallel()
			s := EncodeCursor(Cursor{RecordedAtUs: 1760000000123456, ID: id, Order: order})
			if !strings.HasPrefix(s, CursorPrefix) {
				t.Fatalf("cursor %q lacks prefix", s)
			}
			got, err := DecodeCursor(s, order)
			if err != nil {
				t.Fatal(err)
			}
			if got.RecordedAtUs != 1760000000123456 || got.ID != id || got.Order != order {
				t.Fatalf("round trip = %+v", got)
			}
		})
	}
}

func TestCursorEmptyOrderMeansDesc(t *testing.T) {
	t.Parallel()
	s := EncodeCursor(Cursor{RecordedAtUs: 5, ID: ulid.Make()})
	if _, err := DecodeCursor(s, ""); err != nil {
		t.Fatalf("empty order must decode as desc: %v", err)
	}
	if _, err := DecodeCursor(s, models.AuditOrderAsc); !errors.Is(err, models.ErrBadCursor) {
		t.Fatalf("asc read of a desc cursor = %v, want ErrBadCursor", err)
	}
}

func TestCursorRejectsBadInput(t *testing.T) {
	t.Parallel()
	id := ulid.Make()
	good := EncodeCursor(Cursor{RecordedAtUs: 42, ID: id, Order: models.AuditOrderDesc})
	enc := func(payload string) string {
		return CursorPrefix + base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + checksum(payload)
	}
	flip := []byte(good)
	flip[len(CursorPrefix)+2] ^= 0x01
	tests := []struct {
		name string
		in   string
	}{
		{"empty", ""},
		{"prefix only", CursorPrefix},
		{"legacy cursor", base64.RawURLEncoding.EncodeToString([]byte("1760000000123456:" + id.String()))},
		{"garbage", "!!!not a cursor!!!"},
		{"no checksum", CursorPrefix + base64.RawURLEncoding.EncodeToString([]byte("1:x:d"))},
		{"bad base64", CursorPrefix + "***." + checksum("x")},
		{"flipped payload byte", string(flip)},
		{"truncated", good[:len(good)-3]},
		{"wrong checksum", good[:len(good)-2] + "AA"},
		{"extra segment", enc("1:" + id.String() + ":d:9")},
		{"negative position", enc("-1:" + id.String() + ":d")},
		{"non numeric position", enc("abc:" + id.String() + ":d")},
		{"bad ulid", enc("1:not-a-ulid:d")},
		{"bad order byte", enc("1:" + id.String() + ":x")},
		{"huge position", enc("99999999999999999999:" + id.String() + ":d")},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := DecodeCursor(tc.in, models.AuditOrderDesc); !errors.Is(err, models.ErrBadCursor) {
				t.Fatalf("DecodeCursor(%q) = %v, want ErrBadCursor", tc.in, err)
			}
		})
	}
}

func TestIsLegacyCursor(t *testing.T) {
	t.Parallel()
	if IsLegacyCursor("") || IsLegacyCursor(CursorPrefix+"x") {
		t.Fatal("empty and c1 cursors are not legacy")
	}
	if !IsLegacyCursor("MTIzOmFiYw") {
		t.Fatal("unprefixed cursor is legacy")
	}
}

func TestNormalizeOrder(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{"": "desc", "desc": "desc", "asc": "asc"} {
		if got, ok := NormalizeOrder(in); !ok || got != want {
			t.Fatalf("NormalizeOrder(%q) = %q, %v", in, got, ok)
		}
	}
	if _, ok := NormalizeOrder("ASC"); ok {
		t.Fatal("NormalizeOrder must be case sensitive")
	}
}

func FuzzDecodeCursor(f *testing.F) {
	f.Add(EncodeCursor(Cursor{RecordedAtUs: 1, ID: ulid.Make(), Order: models.AuditOrderAsc}))
	f.Add("c1..")
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		c, err := DecodeCursor(s, models.AuditOrderAsc)
		if err != nil {
			if !errors.Is(err, models.ErrBadCursor) {
				t.Fatalf("error does not wrap ErrBadCursor: %v", err)
			}
			return
		}
		if EncodeCursor(c) != s {
			t.Fatalf("accepted a non canonical cursor %q", s)
		}
	})
}
