package safehttp

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestIsBlockedIP(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		ip   string
		want bool
	}{
		{"loopback v4", "127.0.0.1", true},
		{"loopback v6", "::1", true},
		{"private 10/8", "10.1.2.3", true},
		{"private 172.16/12", "172.16.0.1", true},
		{"private 192.168/16", "192.168.1.1", true},
		{"aws metadata v4", "169.254.169.254", true},
		{"aws metadata v6", "fd00:ec2::254", true},
		{"unique local v6", "fd00::1", true},
		{"link local v6", "fe80::1", true},
		{"cgnat", "100.64.0.1", true},
		{"unspecified", "0.0.0.0", true},
		{"ipv4 mapped loopback", "::ffff:127.0.0.1", true},
		{"ipv4 mapped metadata", "::ffff:169.254.169.254", true},
		{"ipv4 compatible loopback", "::7f00:1", true},
		{"nat64 embedded loopback", "64:ff9b::7f00:1", true},
		{"6to4 embedded loopback", "2002:7f00:1::1", true},
		{"multicast v4", "224.0.0.1", true},
		{"public v4", "8.8.8.8", false},
		{"public v6", "2606:4700:4700::1111", false},
		{"ipv4 mapped public", "::ffff:8.8.8.8", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := IsBlockedIP(netip.MustParseAddr(tc.ip)); got != tc.want {
				t.Fatalf("IsBlockedIP(%s) = %v, want %v", tc.ip, got, tc.want)
			}
		})
	}
}

func TestGuardedControl(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		allowPrivate bool
		address      string
		wantBlocked  bool
	}{
		{"loopback blocked by default", false, "127.0.0.1:443", true},
		{"loopback allowed on opt in", true, "127.0.0.1:443", false},
		{"metadata blocked by default", false, "169.254.169.254:80", true},
		{"unparseable address blocked", false, "not-an-address", true},
		{"public allowed", false, "8.8.8.8:443", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := GuardedControl(tc.allowPrivate)("tcp", tc.address, nil)
			if tc.wantBlocked != errors.Is(err, ErrBlockedAddress) {
				t.Fatalf("err = %v, wantBlocked = %v", err, tc.wantBlocked)
			}
			if !tc.wantBlocked && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestNewClientRefusesLoopback(t *testing.T) {
	t.Parallel()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	t.Cleanup(srv.Close)

	_, err := NewClient(time.Second, false).Get(srv.URL)
	if !errors.Is(err, ErrBlockedAddress) {
		t.Fatalf("err = %v, want ErrBlockedAddress", err)
	}
	if hits.Load() != 0 {
		t.Fatal("blocked server was contacted")
	}
}

func TestNewClientAllowPrivateReachesLoopback(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	t.Cleanup(srv.Close)

	resp, err := NewClient(time.Second, true).Get(srv.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func TestClientRefusesRebindingResolver(t *testing.T) {
	t.Parallel()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	t.Cleanup(srv.Close)
	_, port, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	dialer := &net.Dialer{Timeout: time.Second, Control: GuardedControl(false)}
	c := ClientWithDialer(time.Second, dialer)
	// A public-looking name whose lookup answers a private IP: the guard
	// must judge the address actually dialed, not the hostname.
	c.Transport.(*http.Transport).DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, net.JoinHostPort("127.0.0.1", port))
	}
	_, err = c.Get("http://rebind.example:" + port + "/")
	if !errors.Is(err, ErrBlockedAddress) {
		t.Fatalf("err = %v, want ErrBlockedAddress", err)
	}
	if hits.Load() != 0 {
		t.Fatal("rebound server was contacted")
	}
}

func TestClientDoesNotFollowRedirects(t *testing.T) {
	t.Parallel()
	var targetHits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { targetHits.Add(1) }))
	t.Cleanup(target.Close)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	t.Cleanup(srv.Close)

	resp, err := NewClient(time.Second, true).Get(srv.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302 returned as-is", resp.StatusCode)
	}
	if targetHits.Load() != 0 {
		t.Fatal("redirect was followed")
	}
}
