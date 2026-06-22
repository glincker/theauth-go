package scim_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glincker/theauth-go/internal/models"
	"github.com/glincker/theauth-go/internal/scim"
	"github.com/glincker/theauth-go/internal/ulid"
)

// countingStorage wraps a minimal in-memory SCIM storage and counts every
// SCIMTokenByHash call so tests can assert that Authenticate only performs
// one storage round-trip (perf re-audit 2026-06-21, item 1).
type countingStorage struct {
	tokens     map[string]models.SCIMToken
	hashLookup atomic.Int64
	touchCalls atomic.Int64
}

func newCountingStorage() *countingStorage {
	return &countingStorage{tokens: make(map[string]models.SCIMToken)}
}

func (s *countingStorage) InsertSCIMToken(_ context.Context, t models.SCIMToken) (models.SCIMToken, error) {
	s.tokens[string(t.TokenHash)] = t
	return t, nil
}

func (s *countingStorage) SCIMTokenByHash(_ context.Context, hash []byte) (*models.SCIMToken, error) {
	s.hashLookup.Add(1)
	t, ok := s.tokens[string(hash)]
	if !ok {
		return nil, models.ErrStorageNotFound
	}
	return &t, nil
}

func (s *countingStorage) SCIMTokensByOrg(_ context.Context, orgID models.ULID) ([]models.SCIMToken, error) {
	var out []models.SCIMToken
	for _, t := range s.tokens {
		if t.OrganizationID == orgID {
			out = append(out, t)
		}
	}
	return out, nil
}

func (s *countingStorage) RevokeSCIMTokenByID(_ context.Context, id models.ULID, at time.Time) error {
	for key, t := range s.tokens {
		if t.ID == id {
			t.RevokedAt = &at
			s.tokens[key] = t
			return nil
		}
	}
	return models.ErrStorageNotFound
}

func (s *countingStorage) TouchSCIMTokenLastUsed(_ context.Context, _ models.ULID, _ time.Time) error {
	s.touchCalls.Add(1)
	return nil
}

// seedToken inserts a fresh SCIM token into the counting storage and
// returns the plaintext string.
func seedToken(t *testing.T, st *countingStorage, orgID models.ULID) string {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("rand: %v", err)
	}
	plaintext := base64.RawURLEncoding.EncodeToString(raw)
	hash := sha256.Sum256([]byte(plaintext))
	tok := models.SCIMToken{
		ID:             ulid.New(),
		OrganizationID: orgID,
		Name:           "test",
		TokenHash:      hash[:],
		CreatedAt:      time.Now(),
	}
	if _, err := st.InsertSCIMToken(context.Background(), tok); err != nil {
		t.Fatalf("insert: %v", err)
	}
	return plaintext
}

// TestSCIMAuthSingleLookup verifies that one Authenticate call issues
// SCIMTokenByHash exactly once (perf re-audit 2026-06-21, item 1).
func TestSCIMAuthSingleLookup(t *testing.T) {
	t.Parallel()
	st := newCountingStorage()
	svc := scim.NewService(st, &scim.Config{})
	orgID := ulid.New()
	plaintext := seedToken(t, st, orgID)

	st.hashLookup.Store(0)
	result, err := svc.Authenticate(context.Background(), plaintext)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if result.OrganizationID != orgID {
		t.Errorf("orgID mismatch: got %v, want %v", result.OrganizationID, orgID)
	}
	if got := st.hashLookup.Load(); got != 1 {
		t.Errorf("SCIMTokenByHash called %d times, want exactly 1", got)
	}
}
