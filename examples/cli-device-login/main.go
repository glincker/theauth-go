// Command cli-device-login signs a command-line tool in with the OAuth 2.0
// device authorization grant (RFC 8628). It needs no browser on the machine
// running the CLI: it prints a short code and a URL, the user approves on any
// device, and the CLI polls until it receives tokens.
//
// Try it against the bundled demo server:
//
//	go run ./examples/cli-device-login/server          # prints the exact command below
//	go run ./examples/cli-device-login -issuer http://127.0.0.1:8080 \
//	    -client-id <printed id> -scope profile -resource http://127.0.0.1:8080/api
//
// Only the standard library is used, so the file can be copied into a CLI as
// is. Human-readable progress goes to stderr; with -json the token response is
// written to stdout so it can be piped.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"time"
)

const (
	deviceGrant     = "urn:ietf:params:oauth:grant-type:device_code"
	defaultInterval = 5 * time.Second
	slowDownStep    = 5 * time.Second
	maxResponseSize = 1 << 20
)

type config struct {
	Issuer   string
	ClientID string
	Scope    string
	Resource string
}

// Tokens is the token endpoint response.
type Tokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope,omitempty"`
}

type oauthError struct {
	Code        string `json:"error"`
	Description string `json:"error_description"`
}

func (e *oauthError) Error() string {
	if e.Description == "" {
		return e.Code
	}
	return e.Code + ": " + e.Description
}

// flow carries the side effects so tests can replace them.
type flow struct {
	HTTP  *http.Client
	Out   io.Writer
	Sleep func(ctx context.Context, d time.Duration) error
	Open  func(url string) error // nil means do not try to open a browser
}

func main() {
	var cfg config
	var openBrowser, asJSON bool
	flag.StringVar(&cfg.Issuer, "issuer", "http://127.0.0.1:8080", "authorization server base URL")
	flag.StringVar(&cfg.ClientID, "client-id", "", "OAuth client id registered for the device grant")
	flag.StringVar(&cfg.Scope, "scope", "", "space separated scopes")
	flag.StringVar(&cfg.Resource, "resource", "", "resource indicator (RFC 8707)")
	flag.BoolVar(&openBrowser, "open", false, "try to open the verification page in a browser")
	flag.BoolVar(&asJSON, "json", false, "print the token response as JSON on stdout")
	flag.Parse()
	if cfg.ClientID == "" {
		fmt.Fprintln(os.Stderr, "missing -client-id")
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	f := &flow{HTTP: &http.Client{Timeout: 15 * time.Second}, Out: os.Stderr, Sleep: sleepCtx}
	if openBrowser {
		f.Open = openURL
	}
	tok, err := f.Login(ctx, cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "login failed:", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "Signed in. The access token is valid for %d seconds.\n", tok.ExpiresIn)
	if asJSON {
		_ = json.NewEncoder(os.Stdout).Encode(tok)
	}
}

// Login runs discovery, the device authorization request and the polling loop.
func (f *flow) Login(ctx context.Context, cfg config) (Tokens, error) {
	meta, err := f.discover(ctx, cfg.Issuer)
	if err != nil {
		return Tokens{}, err
	}
	form := url.Values{"client_id": {cfg.ClientID}}
	if cfg.Scope != "" {
		form.Set("scope", cfg.Scope)
	}
	if cfg.Resource != "" {
		form.Set("resource", cfg.Resource)
	}
	var auth struct {
		DeviceCode              string `json:"device_code"`
		UserCode                string `json:"user_code"`
		VerificationURI         string `json:"verification_uri"`
		VerificationURIComplete string `json:"verification_uri_complete"`
		ExpiresIn               int    `json:"expires_in"`
		Interval                int    `json:"interval"`
	}
	if err := f.postForm(ctx, meta.DeviceAuthorizationEndpoint, form, &auth); err != nil {
		return Tokens{}, fmt.Errorf("device authorization: %w", err)
	}

	_, _ = fmt.Fprintf(f.Out, "\nTo sign in, open %s\nand enter the code: %s\n\n", auth.VerificationURI, auth.UserCode)
	if auth.VerificationURIComplete != "" && f.Open != nil {
		if err := f.Open(auth.VerificationURIComplete); err != nil {
			_, _ = fmt.Fprintln(f.Out, "(could not open a browser:", err.Error()+")")
		}
	}
	_, _ = fmt.Fprintf(f.Out, "Waiting for approval (the code expires in %d minutes)...\n", (auth.ExpiresIn+59)/60)

	interval := defaultInterval
	if auth.Interval > 0 {
		interval = time.Duration(auth.Interval) * time.Second
	}
	deadline := time.Duration(auth.ExpiresIn) * time.Second
	var waited time.Duration
	for {
		if err := f.Sleep(ctx, interval); err != nil {
			return Tokens{}, err
		}
		waited += interval
		var tok Tokens
		err := f.postForm(ctx, meta.TokenEndpoint, url.Values{
			"grant_type":  {deviceGrant},
			"device_code": {auth.DeviceCode},
			"client_id":   {cfg.ClientID},
		}, &tok)
		var oe *oauthError
		switch {
		case err == nil:
			return tok, nil
		case !errors.As(err, &oe):
			return Tokens{}, err
		case oe.Code == "authorization_pending":
			// keep polling at the same interval
		case oe.Code == "slow_down":
			interval += slowDownStep
		case oe.Code == "access_denied":
			return Tokens{}, errors.New("the request was denied")
		case oe.Code == "expired_token":
			return Tokens{}, errors.New("the code expired before it was approved")
		default:
			return Tokens{}, oe
		}
		if deadline > 0 && waited > deadline+interval {
			return Tokens{}, errors.New("gave up waiting for approval")
		}
	}
}

type metadata struct {
	TokenEndpoint               string `json:"token_endpoint"`
	DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint"`
}

func (f *flow) discover(ctx context.Context, issuer string) (metadata, error) {
	u := strings.TrimRight(issuer, "/") + "/.well-known/oauth-authorization-server"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return metadata{}, err
	}
	resp, err := f.HTTP.Do(req)
	if err != nil {
		return metadata{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	var m metadata
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseSize)).Decode(&m); err != nil {
		return metadata{}, fmt.Errorf("discovery: %w", err)
	}
	if m.TokenEndpoint == "" || m.DeviceAuthorizationEndpoint == "" {
		return metadata{}, errors.New("the server does not advertise a device authorization endpoint")
	}
	return m, nil
}

// postForm posts form to endpoint. A 2xx response is decoded into out; any
// other response is returned as an *oauthError.
func (f *flow) postForm(ctx context.Context, endpoint string, form url.Values, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := f.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		var oe oauthError
		if json.Unmarshal(body, &oe) != nil || oe.Code == "" {
			return fmt.Errorf("unexpected status %d", resp.StatusCode)
		}
		return &oe
	}
	return json.Unmarshal(body, out)
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func openURL(u string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", u)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", u)
	default:
		cmd = exec.Command("xdg-open", u)
	}
	return cmd.Start()
}
