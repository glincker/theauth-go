// Command theauth-loadtest measures theauth-go against a real Postgres under
// concurrent HTTP load. It has three subcommands: seed (bulk-load users and
// sessions), serve (run theauth on Postgres), and run (drive load, report
// throughput and latency percentiles). See docs/SCALE.md.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/crypto"
	"github.com/glincker/theauth-go/v2/storage/postgres"
	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	password   = "correct-horse-battery-staple"
	cookieName = "theauth_session"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: theauth-loadtest seed|serve|run [flags]")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "seed":
		seed(os.Args[2:])
	case "serve":
		serve(os.Args[2:])
	case "run":
		run(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n", os.Args[1])
		os.Exit(2)
	}
}

func email(i int) string { return fmt.Sprintf("u%d@load.test", i) }
func token(i int) string { return fmt.Sprintf("lt-session-%d", i) }

func userID(i int) [16]byte {
	h := sha256.Sum256([]byte(fmt.Sprintf("lt-user-%d", i)))
	var id [16]byte
	copy(id[:], h[:16])
	id[6] = id[6]&0x0f | 0x40
	id[8] = id[8]&0x3f | 0x80
	return id
}

func sessionID(i int) [16]byte {
	h := sha256.Sum256([]byte(fmt.Sprintf("lt-sess-%d", i)))
	var id [16]byte
	copy(id[:], h[:16])
	id[6] = id[6]&0x0f | 0x40
	id[8] = id[8]&0x3f | 0x80
	return id
}

func seed(args []string) {
	fs := flag.NewFlagSet("seed", flag.ExitOnError)
	dsn := fs.String("db", "postgres://postgres:pw@localhost:55432/ta", "Postgres URL")
	users := fs.Int("users", 100000, "users to create, each with one session")
	_ = fs.Parse(args)

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, *dsn)
	must(err)
	defer pool.Close()
	must(postgres.Migrate(ctx, pool))

	hash, err := crypto.HashPassword(password)
	must(err)
	start := time.Now()
	conn, err := pool.Acquire(ctx)
	must(err)
	defer conn.Release()
	_, err = conn.Exec(ctx, `TRUNCATE users CASCADE`)
	must(err)
	_, err = conn.Conn().CopyFrom(ctx, pgx.Identifier{"users"}, []string{"id", "email", "password_hash"},
		pgx.CopyFromSlice(*users, func(i int) ([]any, error) {
			return []any{userID(i), email(i), hash}, nil
		}))
	must(err)
	expires := time.Now().Add(24 * time.Hour)
	_, err = conn.Conn().CopyFrom(ctx, pgx.Identifier{"sessions"}, []string{"id", "user_id", "token_hash", "expires_at"},
		pgx.CopyFromSlice(*users, func(i int) ([]any, error) {
			return []any{sessionID(i), userID(i), crypto.HashToken(token(i)), expires}, nil
		}))
	must(err)
	_, err = conn.Exec(ctx, `ANALYZE`)
	must(err)
	fmt.Printf("seeded %d users and sessions in %s\n", *users, time.Since(start).Round(time.Millisecond))
}

func serve(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	dsn := fs.String("db", "postgres://postgres:pw@localhost:55432/ta", "Postgres URL")
	addr := fs.String("addr", "127.0.0.1:8090", "listen address")
	maxConns := fs.Int("max-conns", 0, "pgx pool size (0 = pgx default of max(4, NumCPU))")
	hashConc := fs.Int("hash-conc", 0, "concurrent Argon2id computations (0 = library default)")
	_ = fs.Parse(args)

	ctx := context.Background()
	cfg, err := pgxpool.ParseConfig(*dsn)
	must(err)
	if *maxConns > 0 {
		cfg.MaxConns = int32(*maxConns)
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	must(err)
	defer pool.Close()
	must(postgres.Migrate(ctx, pool))

	a, err := theauth.New(theauth.Config{
		Storage:           postgres.New(pool),
		BaseURL:           "http://localhost",
		SecureCookie:      false,
		RateLimitPerIP:    100_000_000,
		RateLimitPerEmail: 100_000_000,
		PasswordPolicy:    theauth.PasswordPolicyConfig{HashConcurrency: *hashConc},
	})
	must(err)
	defer a.Close()
	r := chi.NewRouter()
	a.Mount(r)
	log.Printf("theauth-loadtest serving on %s (pool max %d, GOMAXPROCS %d)", *addr, cfg.MaxConns, runtime.GOMAXPROCS(0))
	log.Fatal(http.ListenAndServe(*addr, r))
}

func run(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	base := fs.String("url", "http://127.0.0.1:8090", "server base URL")
	scenario := fs.String("scenario", "session", "session (GET /auth/me) or signin (POST /auth/email-password/signin)")
	conc := fs.Int("c", 64, "concurrent clients")
	dur := fs.Duration("d", 20*time.Second, "test duration")
	users := fs.Int("users", 100000, "seeded users to draw from")
	_ = fs.Parse(args)

	client := &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: *conc * 2, MaxConnsPerHost: *conc * 2}}
	var okCount, errCount atomic.Int64
	var mu sync.Mutex
	var lat []time.Duration
	deadline := time.Now().Add(*dur)
	var wg sync.WaitGroup
	for w := 0; w < *conc; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			local := make([]time.Duration, 0, 4096)
			for i := w; time.Now().Before(deadline); i += *conc {
				n := i % *users
				var req *http.Request
				if *scenario == "signin" {
					body := fmt.Sprintf(`{"email":%q,"password":%q}`, email(n), password)
					req, _ = http.NewRequest(http.MethodPost, *base+"/auth/email-password/signin", bytes.NewReader([]byte(body)))
					req.Header.Set("Content-Type", "application/json")
				} else {
					req, _ = http.NewRequest(http.MethodGet, *base+"/auth/me", nil)
					req.AddCookie(&http.Cookie{Name: cookieName, Value: token(n)})
				}
				t0 := time.Now()
				resp, err := client.Do(req)
				if err != nil {
					errCount.Add(1)
					continue
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					errCount.Add(1)
					continue
				}
				okCount.Add(1)
				local = append(local, time.Since(t0))
			}
			mu.Lock()
			lat = append(lat, local...)
			mu.Unlock()
		}(w)
	}
	wg.Wait()
	report(*scenario, *conc, *dur, okCount.Load(), errCount.Load(), lat)
}

func report(scenario string, conc int, dur time.Duration, ok, errs int64, lat []time.Duration) {
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	pct := func(p float64) time.Duration {
		if len(lat) == 0 {
			return 0
		}
		return lat[int(float64(len(lat)-1)*p)]
	}
	fmt.Printf("scenario=%s concurrency=%d duration=%s ok=%d errors=%d rps=%.0f p50=%s p95=%s p99=%s max=%s\n",
		scenario, conc, dur, ok, errs, float64(ok)/dur.Seconds(),
		pct(0.50).Round(10*time.Microsecond), pct(0.95).Round(10*time.Microsecond), pct(0.99).Round(10*time.Microsecond), pct(1).Round(10*time.Microsecond))
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
