package postgres

import (
	"testing"

	"github.com/glincker/theauth-go/v2/signals"
	"github.com/glincker/theauth-go/v2/signals/storetest"
)

func TestSignalsStoreContract(t *testing.T) {
	pool := testPool(t)
	t.Cleanup(pool.Close)
	storetest.Run(t, func(t *testing.T) signals.Store {
		_, err := pool.Exec(t.Context(), `TRUNCATE signal_queue, signal_subjects, signal_streams`)
		if err != nil {
			t.Fatal(err)
		}
		return New(pool).SignalsStore()
	})
}
