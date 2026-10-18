package admin

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/glincker/theauth-go/v2/internal/audit"
	"github.com/oklog/ulid/v2"
)

// EncodeCursor returns a URL-safe base64 string of "<unix_micros>:<ulid>".
// Decoding is symmetric and tolerant of any input that round-trips back to
// a parsable (int64, ULID) pair; everything else returns an error.
func EncodeCursor(ts time.Time, id ulid.ULID) string {
	raw := strconv.FormatInt(ts.UnixMicro(), 10) + ":" + id.String()
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

// DecodeCursor reverses EncodeCursor. Returns an error on any malformed
// input; handlers map the error to a 400 problem+json with code
// "pagination.bad_cursor".
func DecodeCursor(s string) (time.Time, ulid.ULID, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return time.Time{}, ulid.ULID{}, fmt.Errorf("cursor decode: %w", err)
	}
	parts := strings.SplitN(string(raw), ":", 2)
	if len(parts) != 2 {
		return time.Time{}, ulid.ULID{}, errors.New("cursor format")
	}
	micros, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return time.Time{}, ulid.ULID{}, fmt.Errorf("cursor micros: %w", err)
	}
	id, err := ulid.Parse(parts[1])
	if err != nil {
		return time.Time{}, ulid.ULID{}, fmt.Errorf("cursor ulid: %w", err)
	}
	return time.UnixMicro(micros), id, nil
}

// EncodeAuditCursor returns the write-order keyset cursor for the audit endpoint: the opaque
// "c1." string for the last row of a page, bound to order ("asc" or "desc"). Clients treat it as
// opaque and send it back as the cursor query parameter.
func EncodeAuditCursor(recordedAtUs int64, id ulid.ULID, order string) string {
	return audit.EncodeCursor(audit.Cursor{RecordedAtUs: recordedAtUs, ID: id, Order: order})
}

// DecodeAuditCursor reverses EncodeAuditCursor and requires the cursor to belong to order. Every
// failure wraps theauth.ErrBadCursor, which handlers map to a 400 with code "pagination.bad_cursor".
func DecodeAuditCursor(s, order string) (recordedAtUs int64, id ulid.ULID, err error) {
	c, err := audit.DecodeCursor(s, order)
	if err != nil {
		return 0, ulid.ULID{}, err
	}
	return c.RecordedAtUs, c.ID, nil
}
