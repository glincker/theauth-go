package integration

import (
	"testing"
)

// TestRequestEndpointsAreEnumerationSafe asserts that endpoints which take an
// email and send a link answer a registered and an unregistered address with
// the same status, body and content type.
func TestRequestEndpointsAreEnumerationSafe(t *testing.T) {
	srv, _ := newTestServer(t)
	known := "enum-known@h.com"
	resp, _ := postJSON(t, srv, "/auth/email-password/signup", map[string]string{
		"email": known, "password": "enum-password-12345",
	}, nil)
	if resp.StatusCode != 201 {
		t.Fatalf("signup: got %d", resp.StatusCode)
	}

	tests := []struct {
		name string
		path string
	}{
		{"magic link request", "/auth/magic-link"},
		{"password reset request", "/auth/email-password/forgot"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rk, bk := postJSON(t, srv, tc.path, map[string]string{"email": known}, nil)
			ru, bu := postJSON(t, srv, tc.path, map[string]string{"email": "enum-unknown-" + tc.name[:5] + "@h.com"}, nil)
			if rk.StatusCode != ru.StatusCode {
				t.Fatalf("status differs: known=%d unknown=%d", rk.StatusCode, ru.StatusCode)
			}
			if rk.StatusCode != 200 {
				t.Fatalf("want 200, got %d", rk.StatusCode)
			}
			if string(bk) != string(bu) {
				t.Fatalf("body differs: known=%q unknown=%q", bk, bu)
			}
			if rk.Header.Get("Content-Type") != ru.Header.Get("Content-Type") {
				t.Fatalf("content-type differs: %q vs %q", rk.Header.Get("Content-Type"), ru.Header.Get("Content-Type"))
			}
		})
	}
}
