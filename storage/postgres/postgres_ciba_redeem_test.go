package postgres

import (
	"testing"

	"github.com/glincker/theauth-go/v2/storagetest"
)

// TestPostgresCIBARedeemContract needs the Postgres test database; testPool
// skips when it is not configured.
func TestPostgresCIBARedeemContract(t *testing.T) {
	storagetest.RunCIBARedeem(t, capsStore(t))
}
