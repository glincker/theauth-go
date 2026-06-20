package ulid

import (
	"crypto/rand"
	"time"

	"github.com/oklog/ulid/v2"
)

// New returns a fresh ULID seeded with crypto/rand.
func New() ulid.ULID {
	return ulid.MustNew(ulid.Timestamp(time.Now()), rand.Reader)
}
