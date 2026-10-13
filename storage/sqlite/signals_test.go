package sqlite_test

import (
	"testing"

	"github.com/glincker/theauth-go/v2/signals"
	"github.com/glincker/theauth-go/v2/signals/storetest"
)

func TestSignalsStoreContract(t *testing.T) {
	storetest.Run(t, func(t *testing.T) signals.Store { return newStore(t).SignalsStore() })
}
