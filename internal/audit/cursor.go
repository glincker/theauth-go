package audit

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"strconv"
	"strings"

	"github.com/glincker/theauth-go/v2/internal/models"
	"github.com/oklog/ulid/v2"
)

// CursorPrefix versions the write-order cursor. A cursor without it is a legacy
// "<created_at micros>:<id>" cursor and keeps decoding for descending reads only.
const CursorPrefix = "c1."

// Cursor is a decoded write-order keyset position: the last row of a page.
// Rows are ordered by (RecordedAtUs, ID) and the next page starts strictly
// after (or before, for descending reads) this position.
type Cursor struct {
	RecordedAtUs int64
	ID           models.ULID
	// Order is models.AuditOrderAsc or models.AuditOrderDesc. A cursor only
	// continues the order that produced it.
	Order string
}

// EncodeCursor returns the opaque cursor string:
//
//	"c1." + base64url("<recorded_at_us>:<ulid>:<a|d>") + "." + base64url(crc32 of the payload)
//
// The checksum catches truncation and accidental edits. It is not a
// signature: a caller can still forge a valid position, which only moves the
// page window and never widens what the caller may read.
func EncodeCursor(c Cursor) string {
	payload := strconv.FormatInt(c.RecordedAtUs, 10) + ":" + c.ID.String() + ":" + orderByte(c.Order)
	return CursorPrefix + base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + checksum(payload)
}

// IsLegacyCursor reports whether s is a non-empty cursor from before write order existed.
func IsLegacyCursor(s string) bool {
	return s != "" && !strings.HasPrefix(s, CursorPrefix)
}

// DecodeCursor parses a "c1." cursor and requires it to match wantOrder
// (models.AuditOrderAsc or models.AuditOrderDesc). Every failure wraps
// models.ErrBadCursor.
func DecodeCursor(s, wantOrder string) (Cursor, error) {
	bad := func(why string) (Cursor, error) {
		return Cursor{}, fmt.Errorf("%w: %s", models.ErrBadCursor, why)
	}
	if !strings.HasPrefix(s, CursorPrefix) {
		return bad("missing version prefix")
	}
	body, sum, ok := strings.Cut(strings.TrimPrefix(s, CursorPrefix), ".")
	if !ok {
		return bad("missing checksum")
	}
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil || base64.RawURLEncoding.EncodeToString(raw) != body {
		// The decoder skips CR and LF, so require the canonical form.
		return bad("payload encoding")
	}
	payload := string(raw)
	if sum != checksum(payload) {
		return bad("checksum")
	}
	parts := strings.Split(payload, ":")
	if len(parts) != 3 {
		return bad("payload shape")
	}
	us, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || us < 0 {
		return bad("position")
	}
	id, err := ulid.ParseStrict(parts[1])
	if err != nil {
		return bad("id")
	}
	order, ok := orderFromByte(parts[2])
	if !ok {
		return bad("order")
	}
	if order != normalizeOrder(wantOrder) {
		return bad("cursor belongs to the other order")
	}
	return Cursor{RecordedAtUs: us, ID: id, Order: order}, nil
}

// NormalizeOrder maps "" to desc and reports false for anything but "", asc or desc.
func NormalizeOrder(o string) (string, bool) {
	switch o {
	case "", models.AuditOrderDesc:
		return models.AuditOrderDesc, true
	case models.AuditOrderAsc:
		return models.AuditOrderAsc, true
	}
	return "", false
}

func normalizeOrder(o string) string {
	n, _ := NormalizeOrder(o)
	return n
}

func orderByte(o string) string {
	if normalizeOrder(o) == models.AuditOrderAsc {
		return "a"
	}
	return "d"
}

func orderFromByte(b string) (string, bool) {
	switch b {
	case "a":
		return models.AuditOrderAsc, true
	case "d":
		return models.AuditOrderDesc, true
	}
	return "", false
}

func checksum(payload string) string {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], crc32.ChecksumIEEE([]byte(payload)))
	return base64.RawURLEncoding.EncodeToString(b[:])
}
