package password

import (
	"context"
	"crypto/sha1" //nolint:gosec // HIBP test fixture
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func hibpServer(t *testing.T, pw string, count string, status int) (*httptest.Server, *string) {
	t.Helper()
	sum := sha1.Sum([]byte(pw)) //nolint:gosec // HIBP test fixture
	full := strings.ToUpper(hex.EncodeToString(sum[:]))
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		_, _ = w.Write([]byte("0018A45C4D1DEF81644B54AB7F969B88D65:0\r\n" + full[5:] + ":" + count + "\r\n00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2\r\n"))
	}))
	t.Cleanup(srv.Close)
	return srv, &gotPath
}

func TestHIBPChecker(t *testing.T) {
	tests := []struct {
		name    string
		count   string
		status  int
		min     int
		want    bool
		wantErr bool
	}{
		{"found", "42", 200, 0, true, false},
		{"found below threshold", "3", 200, 10, false, false},
		{"padding zero is not a hit", "0", 200, 0, false, false},
		{"server error", "1", 500, 0, false, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv, path := hibpServer(t, "password-123", tc.count, tc.status)
			c := &HIBPChecker{BaseURL: srv.URL + "/range/", MinCount: tc.min}
			got, err := c.IsBreached(context.Background(), "password-123")
			if (err != nil) != tc.wantErr || got != tc.want {
				t.Fatalf("got %v err %v", got, err)
			}
			if len(*path) != len("/range/")+5 {
				t.Fatalf("only a 5 char prefix may be sent, path %q", *path)
			}
		})
	}
}

func TestHIBPCheckerUnreachableErrors(t *testing.T) {
	c := &HIBPChecker{BaseURL: "http://127.0.0.1:1/range/", Client: &http.Client{Timeout: 200 * time.Millisecond}}
	if _, err := c.IsBreached(context.Background(), "x"); err == nil {
		t.Fatal("expected error")
	}
}
