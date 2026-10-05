package oauth

import "testing"

func TestValidateRedirectURI(t *testing.T) {
	tests := []struct {
		name     string
		uri      string
		hosts    []string
		insecure bool
		ok       bool
	}{
		{"https", "https://a.example.com/cb", nil, false, true},
		{"localhost http", "http://localhost:8080/cb", nil, false, true},
		{"ipv6 loopback http", "http://[::1]:8080/cb", nil, false, true},
		{"http remote", "http://a.example.com/cb", nil, false, false},
		{"http remote opt in", "http://a.example.com/cb", nil, true, true},
		{"relative", "/cb", nil, false, false},
		{"empty", "", nil, false, false},
		{"opaque", "https:a.example.com", nil, false, false},
		{"fragment", "https://a.example.com/cb#f", nil, false, false},
		{"empty fragment", "https://a.example.com/cb#", nil, false, false},
		{"userinfo", "https://u@a.example.com/cb", nil, false, false},
		{"ftp", "ftp://a.example.com/cb", nil, false, false},
		{"host listed", "https://a.example.com/cb", []string{"a.example.com"}, false, true},
		{"host:port listed", "https://a.example.com:8443/cb", []string{"a.example.com:8443"}, false, true},
		{"port not listed", "https://a.example.com:8443/cb", []string{"a.example.com:443"}, false, false},
		{"bare host matches any port", "https://a.example.com:8443/cb", []string{"a.example.com"}, false, true},
		{"host unlisted", "https://evil.test/cb", []string{"a.example.com"}, false, false},
		{"suffix trick", "https://a.example.com.evil.test/cb", []string{"a.example.com"}, false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateRedirectURI(tc.uri, tc.hosts, tc.insecure)
			if (err == nil) != tc.ok {
				t.Fatalf("validateRedirectURI(%q) err = %v, want ok=%v", tc.uri, err, tc.ok)
			}
		})
	}
}
