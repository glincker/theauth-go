package memory

import (
	"context"
	"sort"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/storage"
	"github.com/oklog/ulid/v2"
)

var _ theauth.TokenVaultStorage = (*Store)(nil)

func vaultKey(userID, provider string) string { return userID + "\x00" + provider }

func cloneVaultCredential(c theauth.VaultCredential) theauth.VaultCredential {
	c.Scopes = append([]string(nil), c.Scopes...)
	c.AccessCT = append([]byte(nil), c.AccessCT...)
	c.RefreshCT = append([]byte(nil), c.RefreshCT...)
	return c
}

func (s *Store) PutVaultCredential(_ context.Context, c theauth.VaultCredential) (theauth.VaultCredential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.vault == nil {
		s.vault = map[string]theauth.VaultCredential{}
	}
	k := vaultKey(c.UserID, c.Provider)
	now := time.Now().UTC()
	c = cloneVaultCredential(c)
	if old, ok := s.vault[k]; ok {
		c.ID, c.CreatedAt, c.Version = old.ID, old.CreatedAt, old.Version+1
	} else {
		if c.ID == "" {
			c.ID = ulid.Make().String()
		}
		c.CreatedAt, c.Version = now, 1
	}
	c.UpdatedAt = now
	s.vault[k] = c
	return cloneVaultCredential(c), nil
}

func (s *Store) VaultCredentialByUserProvider(_ context.Context, userID, provider string) (*theauth.VaultCredential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.vault[vaultKey(userID, provider)]
	if !ok {
		return nil, storage.ErrNotFound
	}
	out := cloneVaultCredential(c)
	return &out, nil
}

func (s *Store) SwapVaultCredential(_ context.Context, c theauth.VaultCredential, expectedVersion int64) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := vaultKey(c.UserID, c.Provider)
	old, ok := s.vault[k]
	if !ok || old.Version != expectedVersion {
		return false, nil
	}
	c = cloneVaultCredential(c)
	c.ID, c.CreatedAt, c.Version, c.UpdatedAt = old.ID, old.CreatedAt, expectedVersion+1, time.Now().UTC()
	s.vault[k] = c
	return true, nil
}

func (s *Store) ListVaultCredentials(_ context.Context, userID string) ([]theauth.VaultCredential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []theauth.VaultCredential
	for _, c := range s.vault {
		if c.UserID == userID {
			out = append(out, cloneVaultCredential(c))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Provider < out[j].Provider })
	return out, nil
}

func (s *Store) ScanVaultCredentials(_ context.Context, afterID string, limit int) ([]theauth.VaultCredential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []theauth.VaultCredential
	for _, c := range s.vault {
		if c.ID > afterID {
			out = append(out, cloneVaultCredential(c))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *Store) DeleteVaultCredential(_ context.Context, userID, provider string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.vault, vaultKey(userID, provider))
	return nil
}
