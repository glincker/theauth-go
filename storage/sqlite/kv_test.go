package sqlite_test

import (
	"context"
	"testing"

	"github.com/glincker/theauth-go/v2/kv"
	"github.com/glincker/theauth-go/v2/kv/kvtest"
	"github.com/glincker/theauth-go/v2/kv/sqlkv"
)

func TestSQLKVContract(t *testing.T) {
	kvtest.Run(t, func(t *testing.T, clk *kvtest.Clock) kv.Cache {
		s, err := sqlkv.New(openDB(t), sqlkv.SQLite, sqlkv.WithClock(clk.Now))
		if err != nil {
			t.Fatal(err)
		}
		ctx := context.Background()
		if err := s.EnsureSchema(ctx); err != nil {
			t.Fatalf("schema: %v", err)
		}
		if err := s.EnsureSchema(ctx); err != nil {
			t.Fatalf("schema is not idempotent: %v", err)
		}
		return s
	})
}

func TestSQLKVPrune(t *testing.T) {
	clk := kvtest.NewClock()
	s, err := sqlkv.New(openDB(t), sqlkv.SQLite, sqlkv.WithClock(clk.Now))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := s.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	_ = s.Set(ctx, "a", []byte("1"), 1)
	_ = s.Set(ctx, "b", []byte("1"), 0)
	clk.Advance(3600 * 1e9)
	if n, err := s.Prune(ctx); err != nil || n != 1 {
		t.Fatalf("prune n=%d err=%v", n, err)
	}
	if _, err := sqlkv.New(openDB(t), sqlkv.SQLite, sqlkv.WithTable("x; DROP TABLE users")); err == nil {
		t.Fatal("hostile table name accepted")
	}
}
