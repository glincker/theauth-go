package cimd

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
		ip   string
		want bool
	}{
		{"127.0.0.1", true},
		{"::1", true},
		{"10.1.2.3", true},
		{"172.16.0.1", true},
		{"192.168.1.1", true},
		{"169.254.169.254", true},
		{"fd00::1", true},
		{"fe80::1", true},
		{"fd00:ec2::254", true},
		{"100.64.0.1", true},
		{"0.0.0.0", true},
		{"0.1.2.3", true},
		{"::7f00:1", true},
		{"::a9fe:a9fe", true},
		{"224.0.0.1", true},
		{"ff02::1", true},
		{"::ffff:127.0.0.1", true},
		{"::ffff:169.254.169.254", true},
		{"64:ff9b::7f00:1", true},
		{"2002:7f00:1::1", true},
		{"8.8.8.8", false},
		{"2606:4700:4700::1111", false},
		{"::ffff:8.8.8.8", false},
	}
	for _, tc := range tests {
		t.Run(tc.ip, func(t *testing.T) {
			t.Parallel()
			if got := IsBlockedIP(netip.MustParseAddr(tc.ip)); got != tc.want {
				t.Fatalf("IsBlockedIP(%s) = %v, want %v", tc.ip, got, tc.want)
			}
		})
	}
}

func TestDefaultClientRefusesLoopback(t *testing.T) {
	t.Parallel()
	ts := newTestServer(t, nil)
	ts.setHandler(serveDoc(Document{ClientID: ts.URL(), RedirectURIs: []string{"https://example.org/cb"}}))
	svc := NewService(Config{TrustPolicy: AllowAnyHTTPS()}, nil)
	_, err := svc.Resolve(context.Background(), ts.URL())
	if !errors.Is(err, ErrFetchFailed) || !errors.Is(err, ErrBlockedAddress) {
		t.Fatalf("err = %v, want ErrFetchFailed wrapping ErrBlockedAddress", err)
	}
	if ts.hits.Load() != 0 {
		t.Fatalf("loopback server was contacted %d times", ts.hits.Load())
	}
}

func TestSafeClientBlocksAtDialTime(t *testing.T) {
	t.Parallel()
	c := newSafeClient(time.Second, false)
	// "localhost" passes any hostname check but resolves to loopback, the
	// same shape as a DNS-rebinding answer.
	for _, target := range []string{"http://localhost:9/x", "http://127.0.0.1:9/x", "http://[::1]:9/x", "http://[::ffff:169.254.169.254]:9/x"} {
		resp, err := c.Get(target)
		if err == nil {
			_ = resp.Body.Close()
			t.Fatalf("%s: expected dial to be refused", target)
		}
		if !errors.Is(err, ErrBlockedAddress) {
			t.Fatalf("%s: err = %v, want ErrBlockedAddress", target, err)
		}
	}
}

func TestSafeClientDoesNotFollowRedirects(t *testing.T) {
	t.Parallel()
	var targetHits atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("/target", func(http.ResponseWriter, *http.Request) { targetHits.Add(1) })
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/target", http.StatusFound)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c := newSafeClient(time.Second, true)
	resp, err := c.Get(srv.URL + "/start")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound || targetHits.Load() != 0 {
		t.Fatalf("status = %d, target hits = %d; redirect must not be followed", resp.StatusCode, targetHits.Load())
	}
}

func TestGuardedControlAllowPrivateOptIn(t *testing.T) {
	t.Parallel()
	if err := guardedControl(true)("tcp", "127.0.0.1:443", nil); err != nil {
		t.Fatalf("opt-in must allow loopback: %v", err)
	}
	if err := guardedControl(false)("tcp", "127.0.0.1:443", nil); !errors.Is(err, ErrBlockedAddress) {
		t.Fatalf("default must block loopback: %v", err)
	}
}

func TestDenyHostHookBlocksBeforeIO(t *testing.T) {
	t.Parallel()
	ts := newTestServer(t, nil)
	svc := NewService(Config{
		TrustPolicy: AllowAnyHTTPS(),
		HTTPClient:  trustingClient(time.Second),
		DenyHost:    func(string) bool { return true },
	}, nil)
	if _, err := svc.Resolve(context.Background(), ts.URL()); !errors.Is(err, ErrPolicyDenied) {
		t.Fatalf("err = %v, want ErrPolicyDenied", err)
	}
	if ts.hits.Load() != 0 {
		t.Fatal("denied host was contacted")
	}
}

func TestSafeClientRefusesRebindingResolver(t *testing.T) {
	t.Parallel()
	ts := newTestServer(t, nil)
	_, port, err := net.SplitHostPort(strings.TrimPrefix(ts.server.URL, "https://"))
	if err != nil {
		t.Fatal(err)
	}
	dialer := &net.Dialer{Timeout: time.Second, Control: guardedControl(false)}
	c := clientWithDialer(time.Second, dialer)
	// A public-looking name whose lookup answers a private IP: the guard
	// must judge the address actually dialed, not the hostname.
	c.Transport.(*http.Transport).DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, net.JoinHostPort("127.0.0.1", port))
	}
	resp, err := c.Get("https://rebind.example:" + port + "/")
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("expected rebound private address to be refused")
	}
	if !errors.Is(err, ErrBlockedAddress) {
		t.Fatalf("err = %v, want ErrBlockedAddress", err)
	}
	if ts.hits.Load() != 0 {
		t.Fatal("rebound server was contacted")
	}
}

func TestResolveRefusesRedirectToPrivateHost(t *testing.T) {
	t.Parallel()
	ts := newTestServer(t, nil)
	ts.setHandler(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://169.254.169.254/latest/meta-data/", http.StatusFound)
	})
	svc := NewService(Config{TrustPolicy: AllowAnyHTTPS(), HTTPClient: newSafeClient(time.Second, true)}, nil)
	if _, err := svc.Resolve(context.Background(), ts.URL()); !errors.Is(err, ErrFetchFailed) {
		t.Fatalf("err = %v, want ErrFetchFailed", err)
	}
}
