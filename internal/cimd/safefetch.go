package cimd

import (
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"

	"github.com/glincker/theauth-go/v2/internal/safehttp"
)

// ErrBlockedAddress is returned when a fetch would connect to a
// non-public address (loopback, private, link-local, CGNAT, metadata).
// It is the same value as safehttp.ErrBlockedAddress.
var ErrBlockedAddress = safehttp.ErrBlockedAddress

// IsBlockedIP reports whether ip must never be the target of a CIMD fetch.
func IsBlockedIP(ip netip.Addr) bool { return safehttp.IsBlockedIP(ip) }

// guardedControl runs after DNS resolution on every connection attempt, so
// a rebinding resolver cannot swap in a private address after validation.
func guardedControl(allowPrivate bool) func(network, address string, _ syscall.RawConn) error {
	return safehttp.GuardedControl(allowPrivate)
}

// newSafeClient builds the default fetch client: dial-time address guard,
// no proxy, no redirects, and the configured timeout.
func newSafeClient(timeout time.Duration, allowPrivate bool) *http.Client {
	return safehttp.NewClient(timeout, allowPrivate)
}

func clientWithDialer(timeout time.Duration, dialer *net.Dialer) *http.Client {
	return safehttp.ClientWithDialer(timeout, dialer)
}
