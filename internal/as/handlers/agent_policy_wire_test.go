package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	internalas "github.com/glincker/theauth-go/v2/internal/as"
	"github.com/glincker/theauth-go/v2/internal/models"
)

func TestWriteTokenErrorAgentPolicy(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		status     int
		code       string
		retryAfter string
		noLeak     string
	}{
		{"policy deny is access_denied", &models.AgentPolicyDeniedError{Action: "files.delete", PolicyID: "secret-policy"}, http.StatusBadRequest, "access_denied", "", "secret-policy"},
		{"rate limit is 429 with Retry-After", &internalas.RateLimitedError{RetryAfter: 1500 * time.Millisecond}, http.StatusTooManyRequests, "rate_limited", "2", ""},
		{"resolver failure is temporarily_unavailable", fmt.Errorf("%w: resolve: %w", models.ErrOAuthServerBusy, errors.New("iam store down")), http.StatusServiceUnavailable, "temporarily_unavailable", "1", "iam store"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			writeTokenError(rec, tc.err)
			if rec.Code != tc.status || !strings.Contains(rec.Body.String(), `"`+tc.code+`"`) {
				t.Fatalf("got %d %s", rec.Code, rec.Body.String())
			}
			if got := rec.Header().Get("Retry-After"); got != tc.retryAfter {
				t.Fatalf("Retry-After %q want %q", got, tc.retryAfter)
			}
			if tc.noLeak != "" && strings.Contains(rec.Body.String(), tc.noLeak) {
				t.Fatalf("body leaks %q: %s", tc.noLeak, rec.Body.String())
			}
		})
	}
}
