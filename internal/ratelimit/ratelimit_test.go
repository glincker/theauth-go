package ratelimit

import (
	"net/http"
	"net/netip"
	"testing"
)

func TestClientIP(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("127.0.0.1/32")}
	cases := []struct {
		name    string
		remote  string
		xff     []string
		trusted []netip.Prefix
		want    string
	}{
		{"no trusted proxies ignores header", "203.0.113.7:1", []string{"9.9.9.9"}, nil, "203.0.113.7"},
		{"untrusted peer ignores header", "203.0.113.7:1", []string{"9.9.9.9"}, trusted, "203.0.113.7"},
		{"single hop", "10.0.0.2:1", []string{"198.51.100.4"}, trusted, "198.51.100.4"},
		{"spoofed leftmost is ignored", "10.0.0.2:1", []string{"1.2.3.4, 198.51.100.4"}, trusted, "198.51.100.4"},
		{"skips trusted proxies from the right", "10.0.0.2:1", []string{"1.2.3.4, 198.51.100.4, 10.0.0.9"}, trusted, "198.51.100.4"},
		{"spoofed entry behind a real client", "10.0.0.2:1", []string{"6.6.6.6, 7.7.7.7, 198.51.100.4"}, trusted, "198.51.100.4"},
		{"multiple header lines are joined", "10.0.0.2:1", []string{"6.6.6.6", "198.51.100.4"}, trusted, "198.51.100.4"},
		{"all trusted returns leftmost", "10.0.0.2:1", []string{"10.1.1.1, 10.2.2.2"}, trusted, "10.1.1.1"},
		{"garbage at the right edge falls back to peer", "10.0.0.2:1", []string{"1.2.3.4, not-an-ip"}, trusted, "10.0.0.2"},
		{"empty header falls back to peer", "10.0.0.2:1", nil, trusted, "10.0.0.2"},
		{"ipv4-mapped ipv6 is normalized", "10.0.0.2:1", []string{"::ffff:198.51.100.4"}, trusted, "198.51.100.4"},
		{"ipv6 client", "10.0.0.2:1", []string{"2001:db8::1"}, trusted, "2001:db8::1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &http.Request{RemoteAddr: tc.remote, Header: http.Header{}}
			for _, v := range tc.xff {
				r.Header.Add("X-Forwarded-For", v)
			}
			if got := ClientIP(r, tc.trusted); got != tc.want {
				t.Fatalf("ClientIP = %q, want %q", got, tc.want)
			}
		})
	}
}
