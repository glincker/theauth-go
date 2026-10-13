package signals_test

import (
	"testing"

	"github.com/glincker/theauth-go/v2/signals"
	"github.com/glincker/theauth-go/v2/signals/storetest"
)

func TestMemoryStoreContract(t *testing.T) {
	storetest.Run(t, func(*testing.T) signals.Store { return signals.NewMemoryStore() })
}
