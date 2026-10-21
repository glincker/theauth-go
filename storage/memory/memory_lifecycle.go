package memory

import (
	"bytes"
	"context"
	"sort"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/storage"
)

var (
	_ theauth.AccountStateStorage  = (*Store)(nil)
	_ theauth.AccountDeleteStorage = (*Store)(nil)
	_ theauth.TrustedDeviceStorage = (*Store)(nil)
)

func (s *Store) AccountStateByUserID(_ context.Context, userID theauth.ULID) (theauth.AccountState, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st := s.acctState[userID]
	if st.DisabledAt != nil {
		at := *st.DisabledAt
		st.DisabledAt = &at
	}
	return st, nil
}

func (s *Store) updateState(userID theauth.ULID, fn func(*theauth.AccountState)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[userID]; !ok {
		return storage.ErrNotFound
	}
	if s.acctState == nil {
		s.acctState = map[theauth.ULID]theauth.AccountState{}
	}
	st := s.acctState[userID]
	fn(&st)
	s.acctState[userID] = st
	return nil
}

func (s *Store) SetMustChangePassword(_ context.Context, userID theauth.ULID, required bool) error {
	return s.updateState(userID, func(st *theauth.AccountState) { st.MustChangePassword = required })
}

func (s *Store) SetUserDisabledAt(_ context.Context, userID theauth.ULID, at *time.Time) error {
	return s.updateState(userID, func(st *theauth.AccountState) {
		if at == nil {
			st.DisabledAt = nil
			return
		}
		v := *at
		st.DisabledAt = &v
	})
}

func (s *Store) DeleteUserCascade(_ context.Context, userID theauth.ULID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[userID]
	if !ok {
		return storage.ErrNotFound
	}
	delete(s.users, userID)
	delete(s.passwordHashes, userID)
	delete(s.acctState, userID)
	delete(s.totpSecrets, userID)
	delete(s.totpSteps, userID)
	for id, v := range s.sessions {
		if v.UserID == userID {
			delete(s.sessions, id)
		}
	}
	for id, v := range s.resetTokens {
		if v.UserID == userID {
			delete(s.resetTokens, id)
		}
	}
	for id, v := range s.magicLinks {
		if v.Email == u.Email {
			delete(s.magicLinks, id)
		}
	}
	for id, v := range s.oauthAccounts {
		if v.UserID == userID {
			delete(s.oauthAccounts, id)
		}
	}
	for id, v := range s.sessionLinks {
		if v.UserID == userID {
			delete(s.sessionLinks, id)
		}
	}
	for id, v := range s.webauthnCreds {
		if v.UserID == userID {
			delete(s.webauthnCreds, id)
		}
	}
	for id, v := range s.recoveryCodes {
		if v.UserID == userID {
			delete(s.recoveryCodes, id)
		}
	}
	for id, v := range s.trusted {
		if v.UserID == userID {
			delete(s.trusted, id)
		}
	}
	s.deleteUserDependents(userID)
	return nil
}

// deleteUserDependents drops the rows held in the sidecar states. The caller
// holds s.mu.
func (s *Store) deleteUserDependents(userID theauth.ULID) {
	if v := s.v07; v != nil {
		for k := range v.members {
			if k.userID == userID {
				delete(v.members, k)
			}
		}
		for id, ident := range v.samlIdentities {
			if ident.UserID == userID {
				delete(v.samlIdentities, id)
			}
		}
		for _, set := range v.groupMembers {
			delete(set, userID)
		}
	}
	if v := s.v10; v != nil {
		for k := range v.userRoles {
			if k.userID == userID {
				delete(v.userRoles, k)
			}
		}
		v.mu.Lock()
		for i := range v.auditRing {
			if a := v.auditRing[i].ActorUserID; a != nil && *a == userID {
				v.auditRing[i].ActorUserID = nil
			}
			// Raw ids are blanked, the chain keeps verifying through the stored pseudonyms.
			if v.auditRing[i].SubjectID == userID.String() {
				v.auditRing[i].SubjectID = ""
			}
			if v.auditRing[i].ApproverID == userID.String() {
				v.auditRing[i].ApproverID = ""
			}
		}
		v.mu.Unlock()
	}
	s.tokens.mu.Lock()
	for id, t := range s.tokens.tokens {
		if t.OwnerID == userID || (t.DelegatedBy != nil && *t.DelegatedBy == userID) {
			delete(s.tokens.tokens, id)
		}
	}
	s.tokens.mu.Unlock()
	if v := s.v20; v != nil {
		v.mu.Lock()
		for code, c := range v.authzCodes {
			if c.UserID == userID {
				delete(v.authzCodes, code)
			}
		}
		for key, t := range v.refreshTokens {
			if t.UserID != nil && *t.UserID == userID {
				delete(v.refreshTokens, key)
			}
		}
		for id, g := range v.delegations {
			if g.UserID == userID {
				delete(v.delegations, id)
			}
		}
		delete(v.delegByUser, userID)
		for id, a := range v.agents {
			if a.OwnerUserID != nil && *a.OwnerUserID == userID {
				delete(v.agents, id)
				delete(v.agentsByClientID, a.ClientID)
			}
		}
		v.mu.Unlock()
	}
}

func (s *Store) InsertTrustedDevice(_ context.Context, d theauth.TrustedDevice) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.trusted == nil {
		s.trusted = map[theauth.ULID]theauth.TrustedDevice{}
	}
	d.TokenHash = bytes.Clone(d.TokenHash)
	s.trusted[d.ID] = d
	return nil
}

func (s *Store) TrustedDeviceByTokenHash(_ context.Context, userID theauth.ULID, hash []byte) (*theauth.TrustedDevice, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, d := range s.trusted {
		if d.UserID == userID && bytes.Equal(d.TokenHash, hash) {
			cp := d
			return &cp, nil
		}
	}
	return nil, storage.ErrNotFound
}

func (s *Store) ListTrustedDevices(_ context.Context, userID theauth.ULID) ([]theauth.TrustedDevice, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := time.Now()
	var out []theauth.TrustedDevice
	for _, d := range s.trusted {
		if d.UserID == userID && d.RevokedAt == nil && d.ExpiresAt.After(now) {
			out = append(out, d)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (s *Store) TouchTrustedDevice(_ context.Context, id theauth.ULID, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.trusted[id]
	if !ok {
		return storage.ErrNotFound
	}
	d.LastUsedAt = at
	s.trusted[id] = d
	return nil
}

func (s *Store) RevokeTrustedDevice(_ context.Context, userID, id theauth.ULID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.trusted[id]
	if !ok || d.UserID != userID || d.RevokedAt != nil {
		return storage.ErrNotFound
	}
	now := time.Now()
	d.RevokedAt = &now
	s.trusted[id] = d
	return nil
}

func (s *Store) RevokeUserTrustedDevices(_ context.Context, userID theauth.ULID) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	n := 0
	for id, d := range s.trusted {
		if d.UserID == userID && d.RevokedAt == nil {
			d.RevokedAt = &now
			s.trusted[id] = d
			n++
		}
	}
	return n, nil
}
