// Command theauth-go is a small developer CLI for theauth-go projects: secret generation,
// OpenAPI export, policy tests, database migrations and project scaffolding. For the security report use theauth-doctor; for user imports use theauth-migrate.
package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/openapi"
	"github.com/glincker/theauth-go/v2/policy/policytest"
	"github.com/glincker/theauth-go/v2/storage/memory"
	"github.com/go-chi/chi/v5"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, rand.Reader))
}

func run(args []string, stdout, stderr io.Writer, entropy io.Reader) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	switch args[0] {
	case "secret":
		return cmdSecret(args[1:], stdout, stderr, entropy)
	case "openapi":
		return cmdOpenAPI(args[1:], stdout, stderr)
	case "policy":
		return cmdPolicy(args[1:], stdout, stderr)
	case "db":
		return cmdDB(args[1:], stdout, stderr)
	case "init":
		return cmdInit(args[1:], stdout, stderr, entropy)
	case "help", "-h", "--help":
		usage(stdout)
		return 0
	default:
		_, _ = fmt.Fprintf(stderr, "unknown command %q\n", args[0])
		usage(stderr)
		return 2
	}
}

func usage(w io.Writer) {
	_, _ = fmt.Fprintln(w, "usage: theauth-go <command> [flags]\n\ncommands:\n  secret   print a random secret (session, OTP or signing key material)\n  openapi  print an OpenAPI 3.1 document for the default route set\n  policy   run a policy test suite: theauth-go policy test <suite.json>\n  db       migration ledger: theauth-go db status|migrate --driver <postgres|mysql> --dsn <dsn>\n  init     scaffold main.go and .env.example in a project directory")
}

func cmdSecret(args []string, stdout, stderr io.Writer, entropy io.Reader) int {
	fs := flag.NewFlagSet("secret", flag.ContinueOnError)
	fs.SetOutput(stderr)
	n := fs.Int("bytes", 32, "number of random bytes (16 to 128)")
	format := fs.String("format", "base64url", "base64url, hex or env")
	name := fs.String("name", "THEAUTH_SECRET", "variable name for --format env")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *n < 16 || *n > 128 {
		_, _ = fmt.Fprintln(stderr, "--bytes must be between 16 and 128")
		return 2
	}
	buf := make([]byte, *n)
	if _, err := io.ReadFull(entropy, buf); err != nil {
		_, _ = fmt.Fprintf(stderr, "entropy: %v\n", err)
		return 1
	}
	b64 := base64.RawURLEncoding.EncodeToString(buf)
	switch *format {
	case "base64url":
		_, _ = fmt.Fprintln(stdout, b64)
	case "hex":
		_, _ = fmt.Fprintln(stdout, hex.EncodeToString(buf))
	case "env":
		_, _ = fmt.Fprintf(stdout, "%s=%s\n", *name, b64)
	default:
		_, _ = fmt.Fprintf(stderr, "unknown --format %q\n", *format)
		return 2
	}
	return 0
}

func cmdOpenAPI(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("openapi", flag.ContinueOnError)
	fs.SetOutput(stderr)
	baseURL := fs.String("base-url", "https://auth.example.com", "public base URL of your server")
	title := fs.String("title", "theauth-go API", "document title")
	version := fs.String("version", "1.0.0", "document version")
	out := fs.String("out", "", "write to this file instead of stdout")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	a, err := theauth.New(theauth.Config{
		Storage:      memory.New(),
		BaseURL:      *baseURL,
		SessionTTL:   time.Hour,
		MagicLinkTTL: 15 * time.Minute,
	})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "build instance: %v\n", err)
		return 1
	}
	defer a.Close()
	r := chi.NewRouter()
	a.Mount(r)
	doc, err := openapi.Generate(r, openapi.Info{Title: *title, Version: *version, ServerURL: *baseURL})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "generate: %v\n", err)
		return 1
	}
	if *out == "" {
		_, _ = fmt.Fprintln(stdout, string(doc))
		return 0
	}
	if err := os.WriteFile(*out, append(doc, '\n'), 0o644); err != nil {
		_, _ = fmt.Fprintf(stderr, "write: %v\n", err)
		return 1
	}
	return 0
}

// cmdPolicy runs `policy test <file>`: it loads a JSON suite, prints one line
// per failing case with the explanation, and exits 1 when any case fails.
func cmdPolicy(args []string, stdout, stderr io.Writer) int {
	if len(args) != 2 || args[0] != "test" {
		_, _ = fmt.Fprintln(stderr, "usage: theauth-go policy test <suite.json>")
		return 2
	}
	s, err := policytest.LoadSuiteFile(args[1])
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 2
	}
	fails := policytest.Run(s)
	for _, f := range fails {
		_, _ = fmt.Fprintln(stderr, f.Error())
	}
	_, _ = fmt.Fprintf(stdout, "%d cases, %d failed\n", len(s.Cases), len(fails))
	if len(fails) > 0 {
		return 1
	}
	return 0
}
