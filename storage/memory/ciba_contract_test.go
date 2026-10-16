package memory

import (
	"testing"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/storagetest"
	"github.com/oklog/ulid/v2"
)

func TestCIBAContract(t *testing.T) {
	storagetest.RunCIBA(t, New(), func(*testing.T) theauth.ULID { return ulid.Make() })
}
