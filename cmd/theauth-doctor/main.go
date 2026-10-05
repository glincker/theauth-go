// Command theauth-doctor fetches the security report of a running theauth-go
// server and prints it. It holds no secrets of its own: the bearer token comes
// from the environment or a file.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/glincker/theauth-go"
)

const (
	exitOK    = 0
	exitFail  = 1
	exitUsage = 2
	tokenEnv  = "THEAUTH_DOCTOR_TOKEN"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, os.Getenv, isTTY(os.Stdout)))
}

func isTTY(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func run(args []string, stdout, stderr io.Writer, getenv func(string) string, tty bool) int {
	fs := flag.NewFlagSet("theauth-doctor", flag.ContinueOnError)
	fs.SetOutput(stderr)
	server := fs.String("server", "", "base URL of the running server, e.g. https://auth.example.com")
	path := fs.String("path", "/auth/admin/doctor", "doctor route path")
	tokenFile := fs.String("token-file", "", "file holding the bearer token (default: $"+tokenEnv+")")
	format := fs.String("format", "table", "output format: table or json")
	failOn := fs.String("fail-on", "", "exit 1 when a finding at or above this severity exists (critical|high|medium|low|info)")
	timeout := fs.Duration("timeout", 15*time.Second, "request timeout")
	noColor := fs.Bool("no-color", false, "disable colors")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *server == "" || (*format != "table" && *format != "json") {
		fmt.Fprintln(stderr, "usage: theauth-doctor --server URL [--token-file F] [--format table|json] [--fail-on SEVERITY]")
		return exitUsage
	}
	threshold := theauth.Severity(*failOn)
	if *failOn != "" && threshold.Rank() == 0 {
		fmt.Fprintf(stderr, "invalid --fail-on %q\n", *failOn)
		return exitUsage
	}
	token, err := loadToken(*tokenFile, getenv)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitUsage
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	rep, err := fetch(ctx, http.DefaultClient, strings.TrimRight(*server, "/")+*path, token)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitFail
	}
	if *format == "json" {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			fmt.Fprintln(stderr, "write json:", err)
			return exitFail
		}
	} else {
		printTable(stdout, rep, tty && !*noColor && getenv("NO_COLOR") == "")
	}
	if threshold.Rank() > 0 && rep.MaxSeverity().Rank() >= threshold.Rank() {
		return exitFail
	}
	return exitOK
}

func loadToken(file string, getenv func(string) string) (string, error) {
	if file != "" {
		b, err := os.ReadFile(file)
		if err != nil {
			return "", fmt.Errorf("read token file: %w", err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	if t := strings.TrimSpace(getenv(tokenEnv)); t != "" {
		return t, nil
	}
	return "", errors.New("no token: set " + tokenEnv + " or pass --token-file")
}

func fetch(ctx context.Context, c *http.Client, url, token string) (theauth.Report, error) {
	var rep theauth.Report
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return rep, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return rep, fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return rep, fmt.Errorf("server returned %s (need a token with the root ability)", resp.Status)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&rep); err != nil {
		return rep, fmt.Errorf("decode report: %w", err)
	}
	return rep, nil
}

func color(sev theauth.Severity) string {
	switch sev {
	case theauth.SeverityCritical:
		return "\x1b[1;31m"
	case theauth.SeverityHigh:
		return "\x1b[31m"
	case theauth.SeverityMedium:
		return "\x1b[33m"
	case theauth.SeverityLow:
		return "\x1b[36m"
	}
	return "\x1b[2m"
}

func printTable(w io.Writer, rep theauth.Report, useColor bool) {
	if len(rep.Findings) == 0 {
		fmt.Fprintln(w, "No findings.")
		return
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "SEVERITY\tID\tTITLE")
	for _, f := range rep.Findings {
		sev := strings.ToUpper(string(f.Severity))
		if useColor {
			sev = color(f.Severity) + sev + "\x1b[0m"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\n", sev, f.ID, f.Title)
	}
	_ = tw.Flush()
	fmt.Fprintf(w, "\n%d critical, %d high, %d medium, %d low, %d info\n",
		rep.Summary[theauth.SeverityCritical], rep.Summary[theauth.SeverityHigh],
		rep.Summary[theauth.SeverityMedium], rep.Summary[theauth.SeverityLow], rep.Summary[theauth.SeverityInfo])
}
