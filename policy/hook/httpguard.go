package hook

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"syscall"
	"time"

	"github.com/glincker/theauth-go/v2/internal/safehttp"
)

// HTTPGuardConfig configures an HTTPGuard.
type HTTPGuardConfig struct {
	// Name identifies the guard in audit records and errors. Required.
	Name string
	// URL is the vendor endpoint. It must be https and must not carry
	// credentials. Plain http is accepted only for localhost, 127.0.0.1 and
	// [::1] with AllowLoopback.
	URL string
	// Secret is the HMAC key shared with the vendor. Required. It is never
	// sent, logged or put in an error.
	Secret string
	// ResponseSecret verifies response signatures. Empty means Secret. A
	// separate key stops a party that can only verify requests from forging
	// responses.
	ResponseSecret string
	// KeyID, when set, is sent as x-theauth-key-id for vendor key rotation.
	KeyID string
	// Tolerance is the max response age or clock skew. Zero means 300s.
	Tolerance time.Duration
	// Headers are extra request headers, such as a vendor API key. They never
	// appear in errors and cannot replace the protocol headers.
	Headers map[string]string
	// Redact, when set, drops or masks fields before the input leaves the
	// process. The default sends the full input, arguments included.
	Redact func(Input) Input
	// AllowLoopback permits loopback destinations (and plain http to a
	// loopback host name) for local development against a vendor stub.
	// Private, link local and metadata ranges stay blocked either way.
	AllowLoopback bool
	// Now is the clock. Nil uses time.Now.
	Now func() time.Time
}

// HTTPGuard is a Hook that asks a vendor endpoint over HTTPS, protocol
// 2026-10. Requests are signed, responses must carry a valid signature bound
// to the request id, bodies are capped at 64 KiB, redirects are refused, and
// the connection goes through a dialer that refuses non public addresses
// (checked after DNS resolution, so a rebinding resolver cannot slip in a
// private address). Every failure is returned as an error, which a Runner
// turns into a deny. Errors name the endpoint origin only.
type HTTPGuard struct {
	name           string
	target         string
	origin         string
	secret         string
	responseSecret string
	keyID          string
	tolerance      time.Duration
	headers        map[string]string
	redact         func(Input) Input
	now            func() time.Time
	client         *http.Client
}

// protocolHeaders are set by the guard and cannot be supplied in Headers.
var protocolHeaders = map[string]bool{
	"Content-Type": true, "Accept": true, "Host": true, "Content-Length": true,
	HeaderTimestamp: true, HeaderSignature: true, HeaderVersion: true, HeaderKeyID: true,
}

// NewHTTPGuard validates cfg and builds the guard with its own hardened
// client. It fails on a missing name or secret, an invalid URL, a URL with
// credentials, or a non https URL that is not an allowed loopback.
func NewHTTPGuard(cfg HTTPGuardConfig) (*HTTPGuard, error) {
	if cfg.Name == "" {
		return nil, errors.New("hook: HTTPGuard needs a Name")
	}
	if cfg.Secret == "" {
		return nil, fmt.Errorf("hook: HTTPGuard %q: secret is required", cfg.Name)
	}
	u, err := checkGuardURL(cfg.Name, cfg.URL, cfg.AllowLoopback)
	if err != nil {
		return nil, err
	}
	headers := make(map[string]string, len(cfg.Headers))
	for k, v := range cfg.Headers {
		ck := http.CanonicalHeaderKey(k)
		if protocolHeaders[ck] {
			return nil, fmt.Errorf("hook: HTTPGuard %q: header %s is set by the protocol", cfg.Name, ck)
		}
		headers[ck] = v
	}
	g := &HTTPGuard{
		name:           cfg.Name,
		target:         u.String(),
		origin:         u.Scheme + "://" + u.Host,
		secret:         cfg.Secret,
		responseSecret: cfg.ResponseSecret,
		keyID:          cfg.KeyID,
		tolerance:      cfg.Tolerance,
		headers:        headers,
		redact:         cfg.Redact,
		now:            cfg.Now,
		client:         newGuardClient(cfg.AllowLoopback),
	}
	if g.responseSecret == "" {
		g.responseSecret = g.secret
	}
	if g.now == nil {
		g.now = time.Now
	}
	return g, nil
}

func checkGuardURL(name, raw string, allowLoopback bool) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Opaque != "" {
		return nil, fmt.Errorf("hook: HTTPGuard %q: url is not valid", name)
	}
	if u.User != nil {
		return nil, fmt.Errorf("hook: HTTPGuard %q: url must not contain credentials", name)
	}
	u.Fragment, u.RawFragment = "", ""
	switch u.Scheme {
	case "https":
		return u, nil
	case "http":
		switch u.Hostname() {
		case "localhost", "127.0.0.1", "::1":
			if allowLoopback {
				return u, nil
			}
		}
	}
	return nil, fmt.Errorf("hook: HTTPGuard %q: url must use https (http is allowed only for a loopback host with AllowLoopback)", name)
}

// dialControl refuses non public addresses at connect time, with a loopback
// exception when allowed.
func dialControl(allowLoopback bool) func(network, address string, c syscall.RawConn) error {
	guarded := safehttp.GuardedControl(false)
	return func(network, address string, c syscall.RawConn) error {
		if allowLoopback {
			if ap, err := netip.ParseAddrPort(address); err == nil && ap.Addr().Unmap().IsLoopback() {
				return nil
			}
		}
		return guarded(network, address, c)
	}
}

// newGuardClient mirrors safehttp.NewClient (dial time address guard, no
// proxy, no redirects) but keeps connections alive: a guard is called on
// every authorization, and a reused connection was already vetted at dial.
// The request context, bounded by the Runner timeout, limits each call; the
// client timeout is only a backstop.
func newGuardClient(allowLoopback bool) *http.Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second, Control: dialControl(allowLoopback)}
	return &http.Client{
		Timeout: MaxTimeout,
		Transport: &http.Transport{
			Proxy:                  nil,
			DialContext:            dialer.DialContext,
			ForceAttemptHTTP2:      true,
			TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout:    10 * time.Second,
			MaxResponseHeaderBytes: 16 << 10,
			MaxIdleConnsPerHost:    16,
			IdleConnTimeout:        90 * time.Second,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// Name returns the configured guard name.
func (g *HTTPGuard) Name() string { return g.name }

// String names the guard and its origin. It never prints the secret, so a
// guard logged with %v or %+v is safe.
func (g *HTTPGuard) String() string { return fmt.Sprintf("HTTPGuard(%s at %s)", g.name, g.origin) }

// GoString is String, so %#v does not dump the secret either.
func (g *HTTPGuard) GoString() string { return g.String() }

func (g *HTTPGuard) errorf(format string, args ...any) error {
	return fmt.Errorf("hook: guard at %s "+format, append([]any{g.origin}, args...)...)
}

// BeforeAuthorize sends one signed check and returns the vendor verdict. Any
// transport error, non 2xx status, redirect, oversize body, missing or wrong
// response signature, stale response, or schema mismatch is an error.
func (g *HTTPGuard) BeforeAuthorize(ctx context.Context, in Input) (Verdict, error) {
	if g.redact != nil {
		in = g.redact(in)
	}
	requestID, err := newRequestID()
	if err != nil {
		return Verdict{}, g.errorf("could not create a request id")
	}
	now := g.now()
	body, err := encodeRequest(requestID, now, in)
	if err != nil {
		return Verdict{}, g.errorf("could not encode the request: %w", err)
	}
	ts := now.Unix()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.target, bytes.NewReader(body))
	if err != nil {
		return Verdict{}, g.errorf("could not build the request")
	}
	for k, v := range g.headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set(HeaderTimestamp, fmt.Sprint(ts))
	req.Header.Set(HeaderSignature, SignGuardBody(g.secret, ts, body))
	req.Header.Set(HeaderVersion, ProtocolVersion)
	if g.keyID != "" {
		req.Header.Set(HeaderKeyID, g.keyID)
	}
	resp, err := g.client.Do(req)
	if err != nil {
		// *url.Error prints the full URL, which may carry a path or query the
		// operator considers private. Keep only the inner cause.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return Verdict{}, g.errorf("request failed: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		_ = resp.Body.Close()
	}()
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return Verdict{}, g.errorf("answered with a redirect, refused")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return Verdict{}, g.errorf("answered HTTP %d", resp.StatusCode)
	}
	if resp.ContentLength > MaxBodyBytes {
		return Verdict{}, g.errorf("response refused: %w", ErrBodyTooLarge)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxBodyBytes+1))
	if err != nil {
		return Verdict{}, g.errorf("response could not be read: %w", err)
	}
	if len(raw) > MaxBodyBytes {
		return Verdict{}, g.errorf("response refused: %w", ErrBodyTooLarge)
	}
	opts := &VerifyOptions{Tolerance: g.tolerance, Now: g.now}
	if err := VerifyGuardResponse(g.responseSecret, requestID, resp.Header, raw, opts); err != nil {
		return Verdict{}, g.errorf("response refused: %w", err)
	}
	v, err := DecodeVerdict(raw)
	if err != nil {
		return Verdict{}, g.errorf("returned a malformed verdict: %w", err)
	}
	if v.Guard == "" {
		v.Guard = g.name
	}
	return v, nil
}
