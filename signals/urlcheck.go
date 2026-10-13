package signals

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"

	"github.com/glincker/theauth-go/v2/internal/safehttp"
)

// ErrUnsafeURL is returned when a receiver supplied URL fails SSRF
// validation.
var ErrUnsafeURL = errors.New("signals: unsafe URL")

// URLPolicy controls ValidateEndpointURL.
type URLPolicy struct {
	// AllowPrivate permits loopback and private destinations. Tests and
	// closed networks only.
	AllowPrivate bool
	// AllowHTTP permits plain http. Implied only by tests.
	AllowHTTP bool
	// Lookup resolves a host. Nil uses the system resolver.
	Lookup func(ctx context.Context, host string) ([]netip.Addr, error)
}

// ValidateEndpointURL checks that raw is a safe push destination: https, no
// credentials, a host that is not (and does not resolve to) a loopback,
// private, link-local, CGNAT or metadata address. The dialer of the delivery
// client repeats the address check at connect time so DNS rebinding cannot
// bypass this one.
func ValidateEndpointURL(ctx context.Context, raw string, p URLPolicy) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("%w: not an absolute URL", ErrUnsafeURL)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !p.AllowHTTP {
			return fmt.Errorf("%w: https required", ErrUnsafeURL)
		}
	default:
		return fmt.Errorf("%w: unsupported scheme %q", ErrUnsafeURL, u.Scheme)
	}
	if u.User != nil {
		return fmt.Errorf("%w: credentials in URL", ErrUnsafeURL)
	}
	if u.Fragment != "" {
		return fmt.Errorf("%w: fragment not allowed", ErrUnsafeURL)
	}
	if p.AllowPrivate {
		return nil
	}
	host := strings.ToLower(u.Hostname())
	if host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".internal") || strings.HasSuffix(host, ".local") {
		return fmt.Errorf("%w: host %q is not public", ErrUnsafeURL, host)
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if safehttp.IsBlockedIP(ip) {
			return fmt.Errorf("%w: address %s is not publicly routable", ErrUnsafeURL, ip)
		}
		return nil
	}
	lookup := p.Lookup
	if lookup == nil {
		lookup = func(ctx context.Context, h string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", h)
		}
	}
	addrs, err := lookup(ctx, host)
	if err != nil || len(addrs) == 0 {
		return fmt.Errorf("%w: host %q does not resolve", ErrUnsafeURL, host)
	}
	for _, a := range addrs {
		if safehttp.IsBlockedIP(a) {
			return fmt.Errorf("%w: host %q resolves to non-public address %s", ErrUnsafeURL, host, a)
		}
	}
	return nil
}
