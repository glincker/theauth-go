package admin

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

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
