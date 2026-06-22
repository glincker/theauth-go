package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	auth0pkg "github.com/glincker/theauth-go/cmd/theauth-migrate/auth0"
	"github.com/glincker/theauth-go/cmd/theauth-migrate/internal"
)

func runAuth0(args []string) error {
	fs := flag.NewFlagSet("auth0", flag.ContinueOnError)
	exportPath := fs.String("export", "", "Path to Auth0 user export JSON file")
	outputPath := fs.String("output", "", "Destination bundle JSON (default: stdout)")
	forceReset := fs.Bool("force-password-reset", false, "Force password reset for all users even when bcrypt hashes are available")
	input, storage, dsn, apply, dryRun, err := parseApplyFlags(fs, args)
	if err != nil {
		return err
	}

	// ----- export mode -----
	if *exportPath != "" {
		return auth0Export(*exportPath, *outputPath, *forceReset)
	}

	// ----- apply mode -----
	if !*apply {
		fs.Usage()
		return fmt.Errorf("specify --export to convert a file, or --input + --apply to write to storage")
	}
	if *input == "" {
		return fmt.Errorf("--input is required with --apply")
	}

	f, err := os.Open(*input)
	if err != nil {
		return fmt.Errorf("open %q: %w", *input, err)
	}
	defer func() { _ = f.Close() }()

	var bundle internal.Bundle
	if err := decodeBundle(f, &bundle); err != nil {
		return err
	}

	st, err := openStorage(*storage, *dsn)
	if err != nil {
		return err
	}

	result, err := internal.ApplyBundle(context.Background(), st, &bundle, internal.ApplyOptions{
		DryRun: *dryRun,
		Out:    os.Stdout,
	})
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "apply errors:\n")
		for _, e := range result.Errors {
			_, _ = fmt.Fprintf(os.Stderr, "  %s\n", e)
		}
		return err
	}
	return nil
}

func auth0Export(exportPath, outputPath string, forceReset bool) error {
	f, err := os.Open(exportPath)
	if err != nil {
		return fmt.Errorf("open %q: %w", exportPath, err)
	}
	defer func() { _ = f.Close() }()

	bundle, err := auth0pkg.ReadJSON(f, forceReset)
	if err != nil {
		return fmt.Errorf("read auth0 export: %w", err)
	}

	_, _ = fmt.Fprintf(os.Stderr, "auth0: read %d users, %d oauth accounts, %d passwords, %d MFA records\n",
		len(bundle.Users), len(bundle.OAuthAccounts), len(bundle.Passwords), len(bundle.MFAEnrolled))
	return writeJSON(outputPath, bundle)
}

// decodeBundle is shared by cmd_cognito.go and cmd_auth0.go.
// It reads a bundle JSON file from f into dst.
func decodeBundle(f *os.File, dst *internal.Bundle) error {
	data, err := os.ReadFile(f.Name())
	if err != nil {
		return fmt.Errorf("read bundle: %w", err)
	}
	if err := jsonUnmarshal(data, dst); err != nil {
		return fmt.Errorf("parse bundle: %w", err)
	}
	return nil
}
