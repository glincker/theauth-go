package sqlite_test

import (
	"crypto/rand"
	"time"

	"github.com/oklog/ulid/v2"
)

func newID() ulid.ULID {
	return ulid.MustNew(ulid.Timestamp(time.Now()), rand.Reader)
}
