package cimd

import (
	"net/url"
	"strings"
	"testing"
)

func FuzzValidateRedirectURI(f *testing.F) {
	for _, s := range []string{"", "https://app.example.com/cb", "HTTPS://App.Example.com/cb", "http://127.0.0.1:8080/cb", "http://localhost/cb", "https://u:p@evil.test/cb", "https://app.example.com/cb#frag", "javascript:alert(1)", "https://app.example.com/\x00", "https://аpp.example.com/cb", "https://" + strings.Repeat("a", 1<<16) + "/cb", "//evil.test/cb", "com.example.app:/cb"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		if ValidateRedirectURI(raw) != nil {
			return
		}
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("accepted unparseable URI %q: %v", raw, err)
		}
		if u.Fragment != "" || strings.Contains(raw, "#") {
			t.Fatalf("accepted fragment: %q", raw)
		}
		if u.User != nil {
			t.Fatalf("accepted userinfo: %q", raw)
		}
		if u.Scheme == "" {
			t.Fatalf("accepted relative URI: %q", raw)
		}
		switch strings.ToLower(u.Scheme) {
		case "javascript", "data", "file", "vbscript":
			t.Fatalf("accepted dangerous scheme: %q", raw)
		}
	})
}
