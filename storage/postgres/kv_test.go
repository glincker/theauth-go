package postgres

import (
	"context"
	"testing"

	"github.com/glincker/theauth-go/v2/kv"
	"github.com/glincker/theauth-go/v2/kv/kvtest"
	"github.com/glincker/theauth-go/v2/kv/sqlkv"
	"github.com/jackc/pgx/v5/stdlib"
)

// TestSQLKVContract runs the kv contract against Postgres through pgx's
// database/sql adapter, the way users wire it: sqlkv.New(stdlib.OpenDBFromPool(pool), sqlkv.Postgres).
func TestSQLKVContract(t *testing.T) {
	pool := testPool(t)
	t.Cleanup(pool.Close)
	db := stdlib.OpenDBFromPool(pool)
	t.Cleanup(func() { _ = db.Close() })
	n := 0
	kvtest.Run(t, func(t *testing.T, clk *kvtest.Clock) kv.Cache {
		n++
		// One table per subtest keeps them independent without truncation.
		table := "theauth_kv_t" + string(rune('a'+n))
		s, err := sqlkv.New(db, sqlkv.Postgres, sqlkv.WithClock(clk.Now), sqlkv.WithTable(table))
		if err != nil {
			t.Fatal(err)
		}
		if err := s.EnsureSchema(context.Background()); err != nil {
			t.Fatalf("schema: %v", err)
		}
		t.Cleanup(func() { _, _ = db.Exec("DROP TABLE IF EXISTS " + table) })
		return s
	})
}
