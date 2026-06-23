package cimd

import "testing"

func TestPolicyGate(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		policy TrustPolicy
		url    string
		want   bool
	}{
		{"deny_all_rejects_https", DenyAll(), "https://example.org/client", false},
		{"deny_all_rejects_empty", DenyAll(), "", false},
		{"allow_any_https_accepts", AllowAnyHTTPS(), "https://example.org/client", true},
		{"allow_any_https_rejects_empty", AllowAnyHTTPS(), "", false},
		{"allow_host_match", AllowHTTPSHost("example.org"), "https://example.org/client", true},
		{"allow_host_case_insensitive_input", AllowHTTPSHost("example.org"), "https://EXAMPLE.org/client", true},
		{"allow_host_case_insensitive_arg", AllowHTTPSHost("EXAMPLE.org"), "https://example.org/client", true},
		{"allow_host_mismatch", AllowHTTPSHost("example.org"), "https://evil.com/client", false},
		{"allow_host_http_rejected", AllowHTTPSHost("example.org"), "http://example.org/client", false},
		{"allow_hosts_multi_match", AllowHTTPSHosts("a.com", "b.com"), "https://b.com/x", true},
		{"allow_hosts_empty_input_denies", AllowHTTPSHosts(), "https://a.com/x", false},
		{"allow_hosts_whitespace_trimmed", AllowHTTPSHosts(" a.com "), "https://a.com/x", true},
		{"allow_host_unparseable_url", AllowHTTPSHost("example.org"), "ht!tps://bad", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.policy.Allow(tc.url)
			if got != tc.want {
				t.Fatalf("Allow(%q) = %v, want %v", tc.url, got, tc.want)
			}
		})
	}
}

func TestDenyAllIsDefault(t *testing.T) {
	t.Parallel()
	svc := NewService(Config{}, nil)
	if svc.cfg.TrustPolicy == nil {
		t.Fatal("expected non-nil default TrustPolicy")
	}
	if svc.cfg.TrustPolicy.Allow("https://example.org/c") {
		t.Fatal("expected default policy to deny")
	}
}
