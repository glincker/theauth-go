package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/glincker/theauth-go/cmd/theauth-migrate/cognito"
	"github.com/glincker/theauth-go/cmd/theauth-migrate/internal"
)

func runCognito(args []string) error {
	fs := flag.NewFlagSet("cognito", flag.ContinueOnError)
	exportPath := fs.String("export", "", "Path to Cognito export file (CSV or JSON)")
	exportFormat := fs.String("export-format", "", `"csv" or "json" (auto-detected when empty)`)
	outputPath := fs.String("output", "", "Destination bundle JSON (default: stdout)")
	input, storage, dsn, apply, dryRun, err := parseApplyFlags(fs, args)
	if err != nil {
		return err
	}

	// ----- export mode -----
	if *exportPath != "" {
		return cognitoExport(*exportPath, *exportFormat, *outputPath)
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
	defer f.Close()

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
		fmt.Fprintf(os.Stderr, "apply errors:\n")
		for _, e := range result.Errors {
			fmt.Fprintf(os.Stderr, "  %s\n", e)
		}
		return err
	}
	return nil
}

func cognitoExport(exportPath, format, outputPath string) error {
	f, err := os.Open(exportPath)
	if err != nil {
		return fmt.Errorf("open %q: %w", exportPath, err)
	}
	defer f.Close()

	// Auto-detect format from extension when not provided.
	if format == "" {
		lower := strings.ToLower(exportPath)
		if strings.HasSuffix(lower, ".csv") {
			format = "csv"
		} else {
			format = "json"
		}
	}

	var bundle *internal.Bundle
	switch format {
	case "csv":
		bundle, err = cognito.ReadCSV(f)
	case "json":
		bundle, err = cognito.ReadJSON(f)
	default:
		return fmt.Errorf("unknown format %q; use csv or json", format)
	}
	if err != nil {
		return fmt.Errorf("read cognito export: %w", err)
	}

	fmt.Fprintf(os.Stderr, "cognito: read %d users, %d MFA records\n",
		len(bundle.Users), len(bundle.MFAEnrolled))
	return writeJSON(outputPath, bundle)
}
