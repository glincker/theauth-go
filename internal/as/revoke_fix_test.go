package as

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2/internal/models"
)

type revokeFailStore struct {
	Storage
	lookupErr error
	rt        *models.RefreshToken
	revokeErr error
	touchErr  error
}

func (r *revokeFailStore) RefreshTokenByHash(context.Context, []byte) (*models.RefreshToken, error) {
	return r.rt, r.lookupErr
}
func (r *revokeFailStore) RevokeRefreshTokenFamily(context.Context, models.ULID, string) error {
	return r.revokeErr
}
func (r *revokeFailStore) UpdateAgentLastActive(context.Context, models.ULID, time.Time) error {
	return r.touchErr
}

func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(old) })
	return &buf
}

func TestRevokeRefreshFamilyLogsIgnoredErrors(t *testing.T) {
	tests := []struct {
		name     string
		store    *revokeFailStore
		wantLog  string
		wantNone bool
	}{
		{"family revoke failure logged", &revokeFailStore{rt: &models.RefreshToken{ClientID: "c"}, revokeErr: errors.New("db down")}, "revoke refresh token family failed", false},
		{"lookup failure other than not found logged", &revokeFailStore{lookupErr: errors.New("db down")}, "refresh token lookup failed", false},
		{"not found is silent", &revokeFailStore{lookupErr: models.ErrStorageNotFound}, "", true},
		{"client mismatch is silent", &revokeFailStore{rt: &models.RefreshToken{ClientID: "other"}}, "", true},
		{"success is silent", &revokeFailStore{rt: &models.RefreshToken{ClientID: "c"}}, "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			buf := captureLogs(t)
			s := &Service{Storage: tc.store}
			s.revokeRefreshFamily(context.Background(), []byte("h"), "c")
			out := buf.String()
			if tc.wantNone && out != "" {
				t.Fatalf("unexpected log: %s", out)
			}
			if !tc.wantNone && !strings.Contains(out, tc.wantLog) {
				t.Fatalf("log %q missing %q", out, tc.wantLog)
			}
		})
	}
}

func TestTouchAgentLogsFailure(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		wantLog bool
	}{
		{"error logged", errors.New("db down"), true},
		{"nil error silent", nil, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			buf := captureLogs(t)
			s := &Service{Storage: &revokeFailStore{touchErr: tc.err}}
			s.touchAgentLastActive(context.Background(), models.ULID{}, time.Now())
			if got := strings.Contains(buf.String(), "agent last active update failed"); got != tc.wantLog {
				t.Fatalf("logged=%v want %v (%s)", got, tc.wantLog, buf.String())
			}
		})
	}
}
