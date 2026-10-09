package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/glincker/theauth-go/v2/cmd/theauth-migrate/internal"
	keycloakpkg "github.com/glincker/theauth-go/v2/cmd/theauth-migrate/keycloak"
)

func runKeycloak(args []string) error {
	fs := flag.NewFlagSet("keycloak", flag.ContinueOnError)
	exportPath := fs.String("export", "", "Path to a Keycloak realm export JSON file")
	outputPath := fs.String("output", "", "Destination bundle JSON (default: stdout)")
	forceReset := fs.Bool("force-password-reset", false, "Force a password reset for every user even when hashes are available")
	input, storage, dsn, apply, dryRun, err := parseApplyFlags(fs, args)
	if err != nil {
		return err
	}

	if *exportPath != "" {
		f, err := os.Open(*exportPath)
		if err != nil {
			return fmt.Errorf("open %q: %w", *exportPath, err)
		}
		defer func() { _ = f.Close() }()
		bundle, err := keycloakpkg.ReadJSON(f, *forceReset)
		if err != nil {
			return fmt.Errorf("read keycloak export: %w", err)
		}
		_, _ = fmt.Fprintf(os.Stderr, "keycloak: read %d users, %d oauth accounts, %d passwords, %d MFA records\n",
			len(bundle.Users), len(bundle.OAuthAccounts), len(bundle.Passwords), len(bundle.MFAEnrolled))
		return writeJSON(*outputPath, bundle)
	}

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
	result, err := internal.ApplyBundle(context.Background(), st, &bundle, internal.ApplyOptions{DryRun: *dryRun, Out: os.Stdout})
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "apply errors:\n")
		for _, e := range result.Errors {
			_, _ = fmt.Fprintf(os.Stderr, "  %s\n", e)
		}
		return err
	}
	return nil
}
