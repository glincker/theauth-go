package storagetest

import (
	"crypto/rand"
	"crypto/sha256"
	"time"

	"github.com/glincker/theauth-go"
	"github.com/oklog/ulid/v2"
)

// newID returns a fresh ULID using crypto/rand.
func newID() theauth.ULID {
	return ulid.MustNew(ulid.Timestamp(time.Now()), rand.Reader)
}

// sha256Hash returns the SHA-256 digest of b as a byte slice.
func sha256Hash(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

// ptr returns a pointer to v.
func ptr[T any](v T) *T {
	return &v
}
