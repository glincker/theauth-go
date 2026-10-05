// Package clientauth lets any Go CLI authenticate against a theauth-go server
// with the RFC 8628 device grant, keep the resulting API token in a local
// store, and call the server with it.
package clientauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	deviceGrantType = "urn:ietf:params:oauth:grant-type:device_code"
	// DefaultAuthPath is where theauth-go mounts its routes.
	DefaultAuthPath = "/auth"
	// DefaultInterval is the RFC 8628 section 3.2 default polling interval.
	DefaultInterval = 5 * time.Second
	// SlowDownStep is the increase RFC 8628 section 3.5 requires on slow_down.
	SlowDownStep = 5 * time.Second
	maxErrBody   = 1 << 14
)

// Errors returned by DeviceLogin, named after their RFC 8628 error codes.
var (
	ErrAccessDenied  = errors.New("clientauth: login was denied")
	ErrDeviceExpired = errors.New("clientauth: device code expired before it was approved")
)

// DevicePrompt is what the user must do to approve a login.
type DevicePrompt struct {
	VerificationURI         string
	VerificationURIComplete string
	UserCode                string
	ExpiresIn               time.Duration
}

// DeviceOptions configures DeviceLogin. Only ServerURL is required.
type DeviceOptions struct {
	// ServerURL is the theauth-go base URL, for example https://app.example.com.
	ServerURL string
	// AuthPath is the route prefix on the server. Default DefaultAuthPath.
	AuthPath string
	// ClientName is shown to the approver. Default: the host name.
	ClientName string
	// Scopes are the abilities to request. Empty uses the server default.
	Scopes []string
	// HTTPClient defaults to http.DefaultClient.
	HTTPClient *http.Client
	// Prompt shows the verification details. Default: print to Out.
	Prompt func(DevicePrompt)
	// Out receives the default prompt. Default os.Stderr.
	Out io.Writer
	// OpenBrowser, when set, is called with the complete verification URI.
	// Its failure is ignored because the printed prompt is the fallback.
	OpenBrowser func(url string) error
	// Store, when set, receives the credential on success.
	Store TokenStore
	// DefaultInterval is used when the server omits one. Default DefaultInterval.
	DefaultInterval time.Duration
	// Sleep waits between polls and must honor ctx. Default: a timer.
	Sleep func(ctx context.Context, d time.Duration) error
	// Now defaults to time.Now.
	Now func() time.Time
}

type deviceCodeResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
}

type oauthError struct {
	Code        string `json:"error"`
	Description string `json:"error_description"`
}

// ServerError is a non-success response from the server.
type ServerError struct {
	Status      int
	Code        string
	Description string
}

func (e *ServerError) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("clientauth: server returned HTTP %d", e.Status)
	}
	return fmt.Sprintf("clientauth: server returned HTTP %d: %s: %s", e.Status, e.Code, e.Description)
}

func (o *DeviceOptions) setDefaults() {
	if o.AuthPath == "" {
		o.AuthPath = DefaultAuthPath
	}
	if o.HTTPClient == nil {
		o.HTTPClient = http.DefaultClient
	}
	if o.Out == nil {
		o.Out = os.Stderr
	}
	if o.DefaultInterval <= 0 {
		o.DefaultInterval = DefaultInterval
	}
	if o.Sleep == nil {
		o.Sleep = sleepCtx
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.ClientName == "" {
		o.ClientName, _ = os.Hostname()
	}
	if o.Prompt == nil {
		out := o.Out
		o.Prompt = func(p DevicePrompt) {
			_, _ = fmt.Fprintf(out, "Open %s and enter the code %s\n", p.VerificationURI, p.UserCode)
		}
	}
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

// DeviceLogin runs the client side of the RFC 8628 device grant and returns the issued credential.
func DeviceLogin(ctx context.Context, opts DeviceOptions) (Credential, error) {
	opts.setDefaults()
	server, err := NormalizeServerURL(opts.ServerURL)
	if err != nil {
		return Credential{}, err
	}
	base := server + "/" + strings.Trim(opts.AuthPath, "/")

	form := url.Values{}
	if opts.ClientName != "" {
		form.Set("client_name", opts.ClientName)
	}
	if len(opts.Scopes) > 0 {
		form.Set("scope", strings.Join(opts.Scopes, " "))
	}
	var dc deviceCodeResponse
	if err := postForm(ctx, opts.HTTPClient, base+"/device/code", form, &dc); err != nil {
		return Credential{}, fmt.Errorf("clientauth: request device code: %w", err)
	}
	if dc.DeviceCode == "" || dc.UserCode == "" {
		return Credential{}, errors.New("clientauth: server returned an incomplete device code response")
	}

	started := opts.Now()
	deadline := started.Add(time.Duration(dc.ExpiresIn) * time.Second)
	interval := time.Duration(dc.Interval) * time.Second
	if interval <= 0 {
		interval = opts.DefaultInterval
	}
	prompt := DevicePrompt{
		VerificationURI: dc.VerificationURI, VerificationURIComplete: dc.VerificationURIComplete,
		UserCode: dc.UserCode, ExpiresIn: time.Duration(dc.ExpiresIn) * time.Second,
	}
	opts.Prompt(prompt)
	if opts.OpenBrowser != nil {
		target := dc.VerificationURIComplete
		if target == "" {
			target = dc.VerificationURI
		}
		_ = opts.OpenBrowser(target)
	}

	poll := url.Values{"grant_type": {deviceGrantType}, "device_code": {dc.DeviceCode}}
	for {
		if err := opts.Sleep(ctx, interval); err != nil {
			return Credential{}, fmt.Errorf("clientauth: waiting for approval: %w", err)
		}
		if dc.ExpiresIn > 0 && !opts.Now().Before(deadline) {
			return Credential{}, ErrDeviceExpired
		}
		var tr tokenResponse
		err := postForm(ctx, opts.HTTPClient, base+"/device/token", poll, &tr)
		if err == nil {
			return finishLogin(ctx, opts, server, tr)
		}
		var se *ServerError
		if !errors.As(err, &se) {
			return Credential{}, fmt.Errorf("clientauth: poll for token: %w", err)
		}
		if se.Status == http.StatusTooManyRequests {
			se.Code = "slow_down"
		}
		switch se.Code {
		case "authorization_pending":
		case "slow_down":
			interval += SlowDownStep
		case "access_denied":
			return Credential{}, ErrAccessDenied
		case "expired_token":
			return Credential{}, ErrDeviceExpired
		default:
			return Credential{}, fmt.Errorf("clientauth: poll for token: %w", err)
		}
	}
}

func finishLogin(ctx context.Context, opts DeviceOptions, server string, tr tokenResponse) (Credential, error) {
	if tr.AccessToken == "" {
		return Credential{}, errors.New("clientauth: server returned an empty access token")
	}
	now := opts.Now().UTC()
	cred := Credential{
		ServerURL: server, AccessToken: tr.AccessToken, TokenType: tr.TokenType,
		Scope: tr.Scope, IssuedAt: now,
	}
	if tr.ExpiresIn > 0 {
		cred.ExpiresAt = now.Add(time.Duration(tr.ExpiresIn) * time.Second)
	}
	if opts.Store != nil {
		if err := opts.Store.Save(ctx, cred); err != nil {
			return cred, fmt.Errorf("clientauth: save credential: %w", err)
		}
	}
	return cred, nil
}

func postForm(ctx context.Context, hc *http.Client, target string, form url.Values, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxErrBody))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return parseServerError(resp.StatusCode, body)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

func parseServerError(status int, body []byte) *ServerError {
	var oe oauthError
	_ = json.Unmarshal(body, &oe)
	return &ServerError{Status: status, Code: oe.Code, Description: oe.Description}
}
