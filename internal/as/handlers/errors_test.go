package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWriteOAuthErrorHidesServerFaultDetail(t *testing.T) {
	tests := []struct {
		name     string
		status   int
		code     string
		detail   string
		wantLeak bool
	}{
		{"500 hides detail", http.StatusInternalServerError, oauthErrServerError, "pq: relation oauth_clients does not exist", false},
		{"server_error code hides detail", http.StatusBadRequest, oauthErrServerError, "dial tcp 10.0.0.5:5432", false},
		{"400 keeps detail", http.StatusBadRequest, oauthErrInvalidRequest, "missing redirect_uri", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			writeOAuthError(rec, tc.status, tc.code, tc.detail)
			if got := strings.Contains(rec.Body.String(), tc.detail); got != tc.wantLeak {
				t.Fatalf("body %q contains detail=%v want %v", rec.Body.String(), got, tc.wantLeak)
			}
		})
	}
}
