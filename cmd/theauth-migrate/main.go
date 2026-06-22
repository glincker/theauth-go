// theauth-migrate is a CLI tool that converts AWS Cognito and Auth0 user
// exports to theauth-go storage rows.
//
// Usage:
//
//	theauth-migrate cognito  --export PATH [--output PATH]
//	theauth-migrate cognito  --input PATH --apply --storage [memory|postgres] [--dsn DSN] [--dry-run]
//	theauth-migrate auth0    --export PATH [--output PATH] [--force-password-reset]
//	theauth-migrate auth0    --input PATH --apply --storage [memory|postgres] [--dsn DSN] [--dry-run]
//	theauth-migrate validate --input PATH
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	sub := os.Args[1]
	switch sub {
	case "cognito":
		if err := runCognito(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "cognito: %v\n", err)
			os.Exit(1)
		}
	case "auth0":
		if err := runAuth0(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "auth0: %v\n", err)
			os.Exit(1)
		}
	case "validate":
		if err := runValidate(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "validate: %v\n", err)
			os.Exit(1)
		}
	case "-h", "--help", "help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown sub-command %q\n\n", sub)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprint(os.Stderr, `theauth-migrate - migrate users from Cognito or Auth0 to theauth-go

SUBCOMMANDS

  cognito   Convert a Cognito user export to the theauth-go intermediate format,
            or apply the intermediate format to a storage backend.

  auth0     Convert an Auth0 user export to the theauth-go intermediate format,
            or apply the intermediate format to a storage backend.

  validate  Validate an intermediate bundle JSON file.

EXPORT (convert vendor file to bundle JSON):

  theauth-migrate cognito --export <path> [--output <path>]
  theauth-migrate auth0   --export <path> [--output <path>] [--force-password-reset]

  --export PATH        Path to the vendor export file (CSV for Cognito, JSON for Auth0).
  --export-format STR  "csv" or "json" (Cognito only; auto-detected if omitted).
  --output PATH        Destination bundle JSON file (default: stdout).

APPLY (write bundle JSON to storage):

  theauth-migrate cognito --input <path> --apply --storage <backend> [options]
  theauth-migrate auth0   --input <path> --apply --storage <backend> [options]

  --input PATH         Path to the intermediate bundle JSON file.
  --apply              Required flag to confirm writes.
  --storage STR        Storage backend: "memory" (test) or "postgres".
  --dsn STR            DSN for postgres (required when --storage postgres).
  --dry-run            Validate + conflict-detect only; no writes.

VALIDATE:

  theauth-migrate validate --input <path>

  --input PATH         Path to the intermediate bundle JSON file.

EXAMPLES

  # Step 1: convert a Cognito CSV export to bundle JSON.
  theauth-migrate cognito --export users.csv --output /tmp/bundle.json

  # Step 2: inspect /tmp/bundle.json, then apply to Postgres.
  theauth-migrate cognito --input /tmp/bundle.json --apply \
    --storage postgres --dsn "postgres://user:pass@host/db"

  # Dry-run only (no writes).
  theauth-migrate cognito --input /tmp/bundle.json --apply --dry-run

  # Auth0 export + apply with bcrypt hash preservation.
  theauth-migrate auth0 --export users.json --output /tmp/bundle.json
  theauth-migrate auth0 --input /tmp/bundle.json --apply \
    --storage postgres --dsn "postgres://user:pass@host/db"

  # Validate a bundle without applying.
  theauth-migrate validate --input /tmp/bundle.json

SEE ALSO

  docs/MIGRATING-FROM-COGNITO.md
  docs/MIGRATING-FROM-AUTH0.md
`)
}

// writeJSON serialises v as indented JSON to path, or stdout when path is "".
func writeJSON(path string, v interface{}) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	if path == "" {
		_, err = os.Stdout.Write(data)
		fmt.Fprintln(os.Stdout)
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}

// loadBundle reads and unmarshals a bundle JSON file from path.
func loadBundle(path string) (*bundleJSON, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", path, err)
	}
	var b bundleJSON
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("parse %q: %w", path, err)
	}
	return &b, nil
}

// bundleJSON is the top-level schema just used to peek at schema_version.
type bundleJSON struct {
	SchemaVersion string `json:"schema_version"`
}

// parseApplyFlags is a helper that adds the --input/--apply/--storage/--dsn/
// --dry-run flags to fs and returns pointers to the parsed values.
func parseApplyFlags(fs *flag.FlagSet, args []string) (input, storage, dsn *string, apply, dryRun *bool, err error) {
	input = fs.String("input", "", "Path to the intermediate bundle JSON file")
	apply = fs.Bool("apply", false, "Write bundle to storage (required to confirm writes)")
	storage = fs.String("storage", "memory", "Storage backend: memory or postgres")
	dsn = fs.String("dsn", "", "DSN for postgres storage")
	dryRun = fs.Bool("dry-run", false, "Validate + conflict-detect only; no writes")
	if err = fs.Parse(args); err != nil {
		return
	}
	return
}
