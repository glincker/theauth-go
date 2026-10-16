package sqlite_test

import (
	"testing"

	"github.com/glincker/theauth-go/v2/storagetest"
)

func TestCIBARedeemContract(t *testing.T) { storagetest.RunCIBARedeem(t, cibaStore(t)) }
