// Package safehttp builds outbound HTTP clients that refuse to connect to
// non-public addresses. It is shared by every feature that fetches a URL
// an untrusted party can influence (CIMD documents, client jwks_uri, ...).
package safehttp

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"
)

// ErrBlockedAddress is returned when a fetch would connect to a
// non-public address (loopback, private, link-local, CGNAT, metadata).
var ErrBlockedAddress = errors.New("safehttp: destination address is not publicly routable")

var blockedPrefixes = mustPrefixes(
	"0.0.0.0/8",         // "this network"
	"::/96",             // deprecated IPv4-compatible IPv6
	"100.64.0.0/10",     // CGNAT
	"192.0.0.0/24",      // IETF protocol assignments
	"198.18.0.0/15",     // benchmarking
	"240.0.0.0/4",       // reserved
	"64:ff9b::/96",      // NAT64, can embed private IPv4
	"2002::/16",         // 6to4, can embed private IPv4
	"100::/64",          // discard-only
	"2001:db8::/32",     // documentation
	"169.254.0.0/16",    // link-local incl. cloud metadata
	"fd00:ec2::254/128", // AWS IMDS over IPv6
)

func mustPrefixes(cidrs ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		out = append(out, netip.MustParsePrefix(c))
	}
	return out
}

// IsBlockedIP reports whether ip must never be the target of a guarded fetch.
func IsBlockedIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.IsUnspecified() || ip.IsLoopback() || ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() {
		return true
	}
	for _, p := range blockedPrefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// GuardedControl returns a net.Dialer.Control function. It runs after DNS
// resolution on every connection attempt, so a rebinding resolver cannot
// swap in a private address after validation.
func GuardedControl(allowPrivate bool) func(network, address string, _ syscall.RawConn) error {
	return func(_, address string, _ syscall.RawConn) error {
		if allowPrivate {
			return nil
		}
		ap, err := netip.ParseAddrPort(address)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrBlockedAddress, err)
		}
		if IsBlockedIP(ap.Addr()) {
			return fmt.Errorf("%w: %s", ErrBlockedAddress, ap.Addr())
		}
		return nil
	}
}

// NewClient builds the default fetch client: dial-time address guard,
// no proxy, no redirects, and the configured timeout.
func NewClient(timeout time.Duration, allowPrivate bool) *http.Client {
	return ClientWithDialer(timeout, &net.Dialer{Timeout: timeout, Control: GuardedControl(allowPrivate)})
}

// ClientWithDialer is NewClient with a caller-supplied dialer, so tests can
// substitute a resolver while keeping the same transport hardening.
func ClientWithDialer(timeout time.Duration, dialer *net.Dialer) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:                 nil,
			DialContext:           dialer.DialContext,
			TLSHandshakeTimeout:   timeout,
			ResponseHeaderTimeout: timeout,
			DisableKeepAlives:     true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}
