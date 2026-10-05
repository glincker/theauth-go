package cimd

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
var ErrBlockedAddress = errors.New("cimd: destination address is not publicly routable")

var blockedPrefixes = mustPrefixes(
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

// IsBlockedIP reports whether ip must never be the target of a CIMD fetch.
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

// guardedControl runs after DNS resolution on every connection attempt, so
// a rebinding resolver cannot swap in a private address after validation.
func guardedControl(allowPrivate bool) func(network, address string, _ syscall.RawConn) error {
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

// newSafeClient builds the default fetch client: dial-time address guard,
// no proxy, no redirects, and the configured timeout.
func newSafeClient(timeout time.Duration, allowPrivate bool) *http.Client {
	return clientWithDialer(timeout, &net.Dialer{Timeout: timeout, Control: guardedControl(allowPrivate)})
}

func clientWithDialer(timeout time.Duration, dialer *net.Dialer) *http.Client {
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
