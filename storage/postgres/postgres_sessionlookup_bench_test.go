package postgres

import (
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2/internal/ulid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const benchSessions = 20000

func seedSessionBench(b *testing.B, pool *pgxpool.Pool) [][]byte {
	b.Helper()
	ctx := b.Context()
	conn, err := pool.Acquire(ctx)
	if err != nil {
		b.Fatal(err)
	}
	defer conn.Release()
	ids := make([][16]byte, benchSessions)
	hashes := make([][]byte, benchSessions)
	for i := range ids {
		ids[i] = [16]byte(ulid.New())
		h := sha256.Sum256([]byte(fmt.Sprintf("bench-%d", i)))
		hashes[i] = h[:]
	}
	if _, err := conn.Conn().CopyFrom(ctx, pgx.Identifier{"users"}, []string{"id", "email"},
		pgx.CopyFromSlice(benchSessions, func(i int) ([]any, error) {
			return []any{ids[i], fmt.Sprintf("bench%d@x.test", i)}, nil
		})); err != nil {
		b.Fatal(err)
	}
	expires := time.Now().Add(time.Hour)
	if _, err := conn.Conn().CopyFrom(ctx, pgx.Identifier{"sessions"}, []string{"id", "user_id", "token_hash", "expires_at"},
		pgx.CopyFromSlice(benchSessions, func(i int) ([]any, error) {
			return []any{[16]byte(ulid.New()), ids[i], hashes[i], expires}, nil
		})); err != nil {
		b.Fatal(err)
	}
	return hashes
}

// BenchmarkSessionLookup compares the two-query session+user lookup with the
// joined one, in parallel, against a real Postgres (POSTGRES_TEST_URL).
func BenchmarkSessionLookup(b *testing.B) {
	pool := testPool(b)
	defer pool.Close()
	s := New(pool)
	hashes := seedSessionBench(b, pool)

	b.Run("two-query", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				h := hashes[i%benchSessions]
				i++
				sess, err := s.SessionByTokenHash(b.Context(), h)
				if err != nil {
					b.Error(err)
					return
				}
				if _, err := s.UserByID(b.Context(), sess.UserID); err != nil {
					b.Error(err)
					return
				}
			}
		})
	})
	b.Run("joined", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				if _, _, err := s.SessionAndUserByTokenHash(b.Context(), hashes[i%benchSessions]); err != nil {
					b.Error(err)
					return
				}
				i++
			}
		})
	})
}
