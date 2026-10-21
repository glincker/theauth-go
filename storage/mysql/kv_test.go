package mysql_test

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"

	"github.com/glincker/theauth-go/v2/kv"
	"github.com/glincker/theauth-go/v2/kv/kvtest"
	"github.com/glincker/theauth-go/v2/kv/sqlkv"
)

// TestSQLKVContract runs the kv contract against MySQL, the way users wire it:
// sqlkv.New(db, sqlkv.MySQL). It needs the same opt in as the storage contract.
func TestSQLKVContract(t *testing.T) {
	if os.Getenv("THEAUTH_MYSQL_CONTRACT") != "1" || os.Getenv("THEAUTH_TEST_MYSQL_DSN") == "" {
		t.Skip("THEAUTH_MYSQL_CONTRACT=1 and THEAUTH_TEST_MYSQL_DSN required; skipping MySQL kv contract")
	}
	db, err := sql.Open("mysql", os.Getenv("THEAUTH_TEST_MYSQL_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	n := 0
	kvtest.Run(t, func(t *testing.T, clk *kvtest.Clock) kv.Cache {
		n++
		// One table per subtest keeps them independent without truncation.
		table := fmt.Sprintf("theauth_kv_t%d", n)
		s, err := sqlkv.New(db, sqlkv.MySQL, sqlkv.WithClock(clk.Now), sqlkv.WithTable(table))
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
