package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/glincker/theauth-go/v2/storage/mysql"
	"github.com/glincker/theauth-go/v2/storage/postgres"
	_ "github.com/go-sql-driver/mysql" // registers the "mysql" database/sql driver
	"github.com/jackc/pgx/v5/pgxpool"
)

const dsnEnv = "THEAUTH_DATABASE_URL"

// migrationRow is one embedded migration and its ledger state, backend neutral.
type migrationRow struct {
	Version   string     `json:"version"`
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Applied   bool       `json:"applied"`
	AppliedAt *time.Time `json:"applied_at"`
	sql       string
}

// dbBackend is the small surface the CLI needs from a storage backend. Tests replace openBackend.
type dbBackend interface {
	Status(ctx context.Context) ([]migrationRow, error)
	Migrate(ctx context.Context) error
	Close()
}

var openBackend = func(ctx context.Context, driver, dsn string) (dbBackend, error) {
	switch driver {
	case "postgres":
		pool, err := pgxpool.New(ctx, dsn)
		if err != nil {
			return nil, err
		}
		if err := pool.Ping(ctx); err != nil {
			pool.Close()
			return nil, err
		}
		return pgBackend{pool}, nil
	case "mysql":
		db, err := sql.Open("mysql", dsn)
		if err != nil {
			return nil, err
		}
		if err := db.PingContext(ctx); err != nil {
			_ = db.Close()
			return nil, err
		}
		return myBackend{db}, nil
	}
	return nil, fmt.Errorf("unsupported driver %q", driver)
}

type pgBackend struct{ pool *pgxpool.Pool }

func (b pgBackend) Close() { b.pool.Close() }
func (b pgBackend) Migrate(ctx context.Context) error {
	return postgres.Migrate(ctx, b.pool)
}
func (b pgBackend) Status(ctx context.Context) ([]migrationRow, error) {
	st, err := postgres.Status(ctx, b.pool)
	if err != nil {
		return nil, err
	}
	rows := make([]migrationRow, len(st))
	for i, s := range st {
		rows[i] = newRow(s.Version, s.Applied, s.AppliedAt, s.SQL)
	}
	return rows, nil
}

type myBackend struct{ db *sql.DB }

func (b myBackend) Close() { _ = b.db.Close() }
func (b myBackend) Migrate(ctx context.Context) error {
	return mysql.Migrate(ctx, b.db)
}
func (b myBackend) Status(ctx context.Context) ([]migrationRow, error) {
	st, err := mysql.Status(ctx, b.db)
	if err != nil {
		return nil, err
	}
	rows := make([]migrationRow, len(st))
	for i, s := range st {
		rows[i] = newRow(s.Version, s.Applied, s.AppliedAt, s.SQL)
	}
	return rows, nil
}

func newRow(version string, applied bool, at time.Time, body string) migrationRow {
	id, name, _ := strings.Cut(version, "_")
	r := migrationRow{Version: version, ID: id, Name: name, Applied: applied, sql: body}
	if applied && !at.IsZero() {
		u := at.UTC()
		r.AppliedAt = &u
	}
	return r
}

var (
	pwKeyValue = regexp.MustCompile(`(?i)(password\s*=\s*)('[^']*'|\S+)`)
	pwMySQL    = regexp.MustCompile(`^([^:@/]*):([^@]*)@`)
)

// redactDSN hides the password in a URL, key=value or MySQL style DSN.
func redactDSN(dsn string) string {
	if strings.Contains(dsn, "://") {
		if u, err := url.Parse(dsn); err == nil {
			if u.User != nil {
				if _, ok := u.User.Password(); ok {
					u.User = url.UserPassword(u.User.Username(), "xxxxx")
				}
			}
			q := u.Query()
			if q.Has("password") {
				q.Set("password", "xxxxx")
				u.RawQuery = q.Encode()
			}
			return u.String()
		}
	}
	out := pwKeyValue.ReplaceAllString(dsn, "${1}xxxxx")
	return pwMySQL.ReplaceAllString(out, "${1}:xxxxx@")
}

// scrub removes the DSN password (and the raw DSN) from an error message.
func scrub(err error, dsn string) string {
	msg := err.Error()
	if dsn == "" {
		return msg
	}
	msg = strings.ReplaceAll(msg, dsn, redactDSN(dsn))
	if u, perr := url.Parse(dsn); perr == nil && u.User != nil {
		if pw, ok := u.User.Password(); ok && pw != "" {
			msg = strings.ReplaceAll(msg, pw, "xxxxx")
		}
	}
	if m := pwMySQL.FindStringSubmatch(dsn); m != nil && m[2] != "" {
		msg = strings.ReplaceAll(msg, m[2], "xxxxx")
	}
	return msg
}

func cmdDB(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || (args[0] != "status" && args[0] != "migrate") {
		_, _ = fmt.Fprintln(stderr, "usage: theauth-go db status|migrate --driver <postgres|mysql> --dsn <dsn> [--json]")
		return 2
	}
	sub := args[0]
	fs := flag.NewFlagSet("db "+sub, flag.ContinueOnError)
	fs.SetOutput(stderr)
	driver := fs.String("driver", "", "postgres or mysql")
	dsn := fs.String("dsn", "", "database DSN (default: $"+dsnEnv+")")
	asJSON := fs.Bool("json", false, "stable JSON output")
	exitCode := fs.Bool("exit-code", false, "status: exit 1 when migrations are pending")
	dryRun := fs.Bool("dry-run", false, "migrate: print the SQL instead of running it")
	to := fs.String("to", "", "migrate: not supported, backends apply every pending migration")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if *dsn == "" {
		*dsn = os.Getenv(dsnEnv)
	}
	switch *driver {
	case "postgres", "mysql":
	case "sqlite":
		_, _ = fmt.Fprintln(stderr, "sqlite is library only: call sqlite.Migrate from storage/sqlite in your own code (see docs/cli.md)")
		return 2
	case "":
		_, _ = fmt.Fprintln(stderr, "--driver is required (postgres or mysql)")
		return 2
	default:
		_, _ = fmt.Fprintf(stderr, "unknown --driver %q (postgres or mysql)\n", *driver)
		return 2
	}
	if *dsn == "" {
		_, _ = fmt.Fprintf(stderr, "no database: pass --dsn or set %s\n", dsnEnv)
		return 2
	}
	if *to != "" {
		_, _ = fmt.Fprintln(stderr, "--to is not supported: the backends apply every pending migration in order")
		return 2
	}
	if sub == "status" && *dryRun || sub == "migrate" && *exitCode {
		_, _ = fmt.Fprintf(stderr, "flag not valid for db %s\n", sub)
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	be, err := openBackend(ctx, *driver, *dsn)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "connect %s: %s\n", redactDSN(*dsn), scrub(err, *dsn))
		return 1
	}
	defer be.Close()
	rows, err := be.Status(ctx)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "status: %s\n", scrub(err, *dsn))
		return 1
	}
	if sub == "status" {
		if err := printStatus(stdout, *driver, *asJSON, rows); err != nil {
			_, _ = fmt.Fprintln(stderr, err)
			return 1
		}
		if *exitCode && len(pending(rows)) > 0 {
			return 1
		}
		return 0
	}
	return runMigrate(ctx, be, *driver, *dsn, *asJSON, *dryRun, rows, stdout, stderr)
}

func pending(rows []migrationRow) []migrationRow {
	var out []migrationRow
	for _, r := range rows {
		if !r.Applied {
			out = append(out, r)
		}
	}
	return out
}

func printStatus(w io.Writer, driver string, asJSON bool, rows []migrationRow) error {
	p := len(pending(rows))
	if asJSON {
		return writeJSON(w, map[string]any{
			"driver": driver, "applied": len(rows) - p, "pending": p, "migrations": rows,
		})
	}
	for _, r := range rows {
		state := "pending"
		if r.Applied {
			state = "applied"
			if r.AppliedAt != nil {
				state += " " + r.AppliedAt.Format(time.RFC3339)
			}
		}
		_, _ = fmt.Fprintf(w, "%-6s %-32s %s\n", r.ID, r.Name, state)
	}
	_, _ = fmt.Fprintf(w, "%d applied, %d pending\n", len(rows)-p, p)
	return nil
}

func runMigrate(ctx context.Context, be dbBackend, driver, dsn string, asJSON, dryRun bool, rows []migrationRow, stdout, stderr io.Writer) int {
	todo := pending(rows)
	ids := make([]string, len(todo))
	for i, r := range todo {
		ids[i] = r.Version
	}
	if dryRun {
		if asJSON {
			sqls := map[string]string{}
			for _, r := range todo {
				sqls[r.Version] = r.sql
			}
			return jsonOrFail(stdout, stderr, map[string]any{"driver": driver, "dry_run": true, "pending": ids, "sql": sqls})
		}
		for _, r := range todo {
			_, _ = fmt.Fprintf(stdout, "-- migration %s\n%s\n", r.Version, strings.TrimSpace(r.sql))
		}
		_, _ = fmt.Fprintf(stdout, "-- %d pending (dry run, nothing executed)\n", len(todo))
		return 0
	}
	if len(todo) > 0 {
		if err := be.Migrate(ctx); err != nil {
			_, _ = fmt.Fprintf(stderr, "migrate: %s\n", scrub(err, dsn))
			return 1
		}
	}
	if asJSON {
		return jsonOrFail(stdout, stderr, map[string]any{"driver": driver, "dry_run": false, "applied": ids})
	}
	for _, id := range ids {
		_, _ = fmt.Fprintf(stdout, "applied %s\n", id)
	}
	_, _ = fmt.Fprintf(stdout, "%d migrations applied\n", len(ids))
	return 0
}

func jsonOrFail(stdout, stderr io.Writer, v any) int {
	if err := writeJSON(stdout, v); err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func writeJSON(w io.Writer, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return errors.New("encode json: " + err.Error())
	}
	_, err = fmt.Fprintln(w, string(b))
	return err
}
