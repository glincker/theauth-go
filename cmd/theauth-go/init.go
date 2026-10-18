package main

import (
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/glincker/theauth-go/v2/internal/emailnorm"
	"github.com/glincker/theauth-go/v2/internal/password"
)

// seedUser is the optional user created by the generated main.go through TheAuth.CreateUser.
type seedUser struct {
	Email string
	Name  string
}

// muxLine marks where the seed block is inserted in the generated main.go.
const muxLine = "\tmux := http.NewServeMux()\n"

// validateSeedEmail applies the library's own normalization (emailnorm, the function CreateUser
// uses with the default config) and its address parser. It rejects only input that is obviously not
// a bare address; CreateUser performs the authoritative validation at runtime.
func validateSeedEmail(raw string) (string, error) {
	canonical := emailnorm.Normalizer{}.Normalize(raw)
	if canonical == "" || len(canonical) > 320 {
		return "", errors.New("must be 1 to 320 characters")
	}
	parsed, err := password.ValidateEmail(canonical)
	if err != nil || parsed != canonical {
		return "", errors.New("must be a bare address such as ada@example.com")
	}
	return canonical, nil
}

// seedNotice is printed whenever --seed-email is used.
const seedNotice = "note: the seed user is written to main.go as a commented-out CreateUser call. " +
	"CreateUser makes a user with no credential, and any existing user closes the Bootstrap gate, " +
	"so enabling it would leave nobody able to set a password with the setup token. " +
	"Uncomment it only after you add another sign-in method (passkey, OAuth or a reset email flow)."

// seedBlock renders the CreateUser call placed after theauth.New. It is empty without a seed email.
// The call is commented out: the generated config signs in through Bootstrap and a password, and a
// user created by CreateUser has no credential and counts as an existing user, which closes the
// Bootstrap gate (signup then returns signup closed). Leaving it active would lock the operator out.
func seedBlock(s seedUser) string {
	if s.Email == "" {
		return ""
	}
	in := "Email: " + strconv.Quote(s.Email)
	if s.Name != "" {
		in += ", Name: " + strconv.Quote(s.Name)
	}
	return "\t// Seed user (disabled). CreateUser is idempotent but creates NO password, passkey or session,\n" +
		"\t// and a user that exists closes the Bootstrap gate: the setup token no longer allows signup,\n" +
		"\t// so this address could never get a password. Enable it only when you add another way to sign\n" +
		"\t// in (passkey, OAuth, or a password reset email flow), and remove Bootstrap or sign up first.\n" +
		"\t//\n" +
		"\t// seed, err := a.CreateUser(ctx, theauth.CreateUserInput{" + in + "})\n" +
		"\t// if err != nil {\n\t// \tlog.Fatalf(\"seed user: %v\", err)\n\t// }\n" +
		"\t// slog.Info(\"seed user ready\", \"user_id\", seed.ID.String())\n\n"
}

// mainTemplate pieces. The scaffold never touches the network: the go get command is printed.
const (
	mainHead = `package main

import (
	"context"
	"encoding/base64"
	"log"
	"log/slog"
	"net/http"
	"os"

	"github.com/glincker/theauth-go/v2"
`
	mainMemoryImport = `	"github.com/glincker/theauth-go/v2/storage/memory"
`
	mainPostgresImport = `	"github.com/glincker/theauth-go/v2/storage/postgres"
	"github.com/jackc/pgx/v5/pgxpool"
`
	mainMySQLImport = `	"database/sql"

	"github.com/glincker/theauth-go/v2/storage/mysql"
	_ "github.com/go-sql-driver/mysql"
`
	mainBody = `)

func main() {
	ctx := context.Background()
	store := openStorage(ctx)

	key, err := base64.RawURLEncoding.DecodeString(os.Getenv("THEAUTH_ENCRYPTION_KEY"))
	if err != nil || len(key) != 32 {
		log.Fatal("THEAUTH_ENCRYPTION_KEY must be 32 bytes, base64url (see .env.example)")
	}

	a, err := theauth.New(theauth.Config{
		Storage:       store,
		BaseURL:       envOr("BASE_URL", "http://localhost:8080"),
		EncryptionKey: key,
		// The first signup needs this one-time token (X-Setup-Token header or setupToken field).
		Bootstrap: &theauth.BootstrapConfig{SetupToken: os.Getenv("THEAUTH_SETUP_TOKEN")},
	})
	if err != nil {
		log.Fatal(err)
	}
	defer a.Close()

	mux := http.NewServeMux()
	mux.Handle("/auth/", a.Handler())
	addr := envOr("ADDR", ":8080")
	slog.Info("listening", "addr", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

`
	storageMemory = `func openStorage(_ context.Context) theauth.Storage { return memory.New() }
`
	storagePostgres = `// Run "theauth-go db migrate --driver postgres" before the first start.
func openStorage(ctx context.Context) theauth.Storage {
	pool, err := pgxpool.New(ctx, os.Getenv("THEAUTH_DATABASE_URL"))
	if err != nil {
		log.Fatal(err)
	}
	return postgres.New(pool)
}
`
	storageMySQL = `// Run "theauth-go db migrate --driver mysql" before the first start.
func openStorage(_ context.Context) theauth.Storage {
	db, err := sql.Open("mysql", os.Getenv("THEAUTH_DATABASE_URL"))
	if err != nil {
		log.Fatal(err)
	}
	return mysql.New(db)
}
`
	composeTemplate = `services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: theauth
      POSTGRES_PASSWORD: ${THEAUTH_PG_PASSWORD:?copy .env.example to .env}
      POSTGRES_DB: theauth
    ports:
      - "5432:5432"
    volumes:
      - theauth_pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U theauth"]
      interval: 5s
      timeout: 3s
      retries: 10

volumes:
  theauth_pgdata:
`
)

func renderMain(storage string, seed seedUser) string {
	var b strings.Builder
	b.WriteString(mainHead)
	switch storage {
	case "postgres":
		b.WriteString(mainPostgresImport)
	case "mysql":
		b.WriteString(mainMySQLImport)
	default:
		b.WriteString(mainMemoryImport)
	}
	b.WriteString(strings.Replace(mainBody, muxLine, seedBlock(seed)+muxLine, 1))
	switch storage {
	case "postgres":
		b.WriteString(storagePostgres)
	case "mysql":
		b.WriteString(storageMySQL)
	default:
		b.WriteString(storageMemory)
	}
	return b.String()
}

func renderEnv(storage string, withPostgres bool, entropy io.Reader) (string, error) {
	gen := func() (string, error) {
		buf := make([]byte, 32)
		if _, err := io.ReadFull(entropy, buf); err != nil {
			return "", err
		}
		return base64.RawURLEncoding.EncodeToString(buf), nil
	}
	enc, err := gen()
	if err != nil {
		return "", err
	}
	tok, err := gen()
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "BASE_URL=http://localhost:8080\nADDR=:8080\nTHEAUTH_ENCRYPTION_KEY=%s\nTHEAUTH_SETUP_TOKEN=%s\n", enc, tok)
	if withPostgres {
		pw, err := gen()
		if err != nil {
			return "", err
		}
		pw = strings.NewReplacer("-", "a", "_", "b").Replace(pw) // keep it URL safe without escaping
		fmt.Fprintf(&b, "THEAUTH_PG_PASSWORD=%s\nTHEAUTH_DATABASE_URL=postgres://theauth:%s@localhost:5432/theauth\n", pw, pw)
	} else if storage == "postgres" {
		b.WriteString("THEAUTH_DATABASE_URL=postgres://user:password@localhost:5432/theauth\n")
	} else if storage == "mysql" {
		b.WriteString("THEAUTH_DATABASE_URL=user:password@tcp(localhost:3306)/theauth?parseTime=true&loc=UTC\n")
	}
	return b.String(), nil
}

func cmdInit(args []string, stdout, stderr io.Writer, entropy io.Reader) int {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", ".", "project directory")
	storage := fs.String("storage", "memory", "memory, postgres or mysql")
	printOnly := fs.Bool("print", false, "print main.go to stdout and write nothing")
	force := fs.Bool("force", false, "overwrite existing files")
	seedEmail := fs.String("seed-email", "", "write a commented-out CreateUser call for this user into main.go (a seeded user has no credential and closes the Bootstrap gate, see docs/cli.md)")
	seedName := fs.String("seed-name", "", "display name for --seed-email")
	withPG := fs.Bool("with-postgres", false, "also write docker-compose.yml with a postgres service (implies --storage postgres)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *withPG {
		*storage = "postgres"
	}
	switch *storage {
	case "memory", "postgres", "mysql":
	default:
		_, _ = fmt.Fprintf(stderr, "unknown --storage %q (memory, postgres or mysql)\n", *storage)
		return 2
	}
	var seed seedUser
	if *seedEmail != "" {
		canonical, err := validateSeedEmail(*seedEmail)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "invalid --seed-email: %v\n", err)
			return 2
		}
		seed = seedUser{Email: canonical, Name: strings.TrimSpace(*seedName)}
	} else if *seedName != "" {
		_, _ = fmt.Fprintln(stderr, "--seed-name needs --seed-email")
		return 2
	}
	mainSrc := renderMain(*storage, seed)
	if seed.Email != "" {
		notice := stdout
		if *printOnly {
			notice = stderr // keep stdout clean so it can be redirected to main.go
		}
		_, _ = fmt.Fprintln(notice, seedNotice)
	}
	if *printOnly {
		_, _ = fmt.Fprint(stdout, mainSrc)
		return 0
	}
	env, err := renderEnv(*storage, *withPG, entropy)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "entropy: %v\n", err)
		return 1
	}
	files := []struct{ name, body string }{{"main.go", mainSrc}, {".env.example", env}}
	if *withPG {
		files = append(files, struct{ name, body string }{"docker-compose.yml", composeTemplate})
	}
	if err := os.MkdirAll(*dir, 0o755); err != nil {
		_, _ = fmt.Fprintf(stderr, "mkdir: %v\n", err)
		return 1
	}
	for _, f := range files {
		path := filepath.Join(*dir, f.name)
		mode := os.O_WRONLY | os.O_CREATE | os.O_EXCL
		if *force {
			mode = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
		}
		perm := os.FileMode(0o644)
		if f.name == ".env.example" {
			perm = 0o600
		}
		h, err := os.OpenFile(path, mode, perm)
		if os.IsExist(err) {
			_, _ = fmt.Fprintf(stdout, "skip %s (exists, use --force to overwrite)\n", f.name)
			continue
		}
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "write %s: %v\n", f.name, err)
			return 1
		}
		_, werr := h.WriteString(f.body)
		if cerr := h.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			_, _ = fmt.Fprintf(stderr, "write %s: %v\n", f.name, werr)
			return 1
		}
		_, _ = fmt.Fprintf(stdout, "wrote %s\n", f.name)
	}
	if _, err := os.Stat(filepath.Join(*dir, "go.mod")); err != nil {
		_, _ = fmt.Fprintln(stdout, "no go.mod found. Run: go mod init <module>")
	}
	_, _ = fmt.Fprintln(stdout, "next: go get github.com/glincker/theauth-go/v2@latest && go mod tidy")
	_, _ = fmt.Fprintln(stdout, "then: cp .env.example .env, load it into your shell, and go run .")
	return 0
}
