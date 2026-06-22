package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/glincker/theauth-go/cmd/theauth-migrate/internal"
)

func runValidate(args []string) error {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	inputPath := fs.String("input", "", "Path to the intermediate bundle JSON file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *inputPath == "" {
		return fmt.Errorf("--input is required")
	}

	data, err := os.ReadFile(*inputPath)
	if err != nil {
		return fmt.Errorf("read %q: %w", *inputPath, err)
	}

	var bundle internal.Bundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return fmt.Errorf("parse bundle: %w", err)
	}

	result := internal.ValidateBundle(&bundle)
	for _, w := range result.Warnings {
		fmt.Fprintf(os.Stderr, "WARN: %s\n", w)
	}
	if !result.OK() {
		for _, e := range result.Errors {
			fmt.Fprintf(os.Stderr, "ERROR: %s\n", e)
		}
		return fmt.Errorf("validation failed with %d error(s)", len(result.Errors))
	}

	fmt.Fprintf(os.Stdout, "OK: bundle is valid (%d users, %d oauth, %d passwords, %d mfa, %d sessions)\n",
		len(bundle.Users), len(bundle.OAuthAccounts), len(bundle.Passwords),
		len(bundle.MFAEnrolled), len(bundle.Sessions))
	return nil
}

// jsonUnmarshal is a package-level helper so cmd_auth0.go can call it.
func jsonUnmarshal(data []byte, v interface{}) error {
	return json.Unmarshal(data, v)
}
