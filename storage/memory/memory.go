package memory

import (
	"bytes"
	"context"
	"sync"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/crypto"
	"github.com/glincker/theauth-go/v2/storage"
)

type Store struct {
	mu             sync.RWMutex
	users          map[theauth.ULID]theauth.User
	sessions       map[theauth.ULID]theauth.Session
	magicLinks     map[theauth.ULID]theauth.MagicLink
	passwordHashes map[theauth.ULID]string
	resetTokens    map[theauth.ULID]theauth.PasswordResetToken
	oauthAccounts  map[theauth.ULID]theauth.OAuthAccount
	// sessionLinks backs SessionLinkStorage; see memory_sessions.go.
	sessionLinks  map[theauth.ULID]theauth.SessionLink
	webauthnCreds map[theauth.ULID]theauth.WebAuthnCredential
	totpSecrets   map[theauth.ULID]theauth.TOTPSecret
	recoveryCodes map[theauth.ULID]theauth.RecoveryCode
	totpSteps     map[theauth.ULID]int64
	// toolApprovals backs ToolApprovalStorage; see memory_toolapprovals.go.
	toolApprovals map[string]theauth.ToolApproval
	// vault backs TokenVaultStorage; see memory_tokenvault.go.
	vault map[string]theauth.VaultCredential
	// v0.7 multi-tenancy, SAML and SCIM state; see memory_v07.go.
	v07 *v07State
	// v1.0 RBAC + audit. See memory_v10.go.
	v10 *v10State
	// v2.0 phase 1 + 2: OAuth 2.1 AS + DCR + JWKS. See memory_v20.go.
	v20 *v20State
	// PAR (RFC 9126): pushed authorization requests. See memory_par.go.
	parInitMu sync.Mutex
	par       *parState
	// jti: RFC 7523 JTI replay cache. See memory_jwtbearer.go.
	jti     *jtiState
	jtiOnce sync.Once
	// CIBA: backchannel authentication requests. See memory_ciba.go.
	ciba *cibaState
	// scoped API tokens + device codes. See memory_apitokens.go.
	tokens tokenState
	// OAuth device authorizations + registration tokens. See memory_device.go.
	devauth devAuthState
	iotdev  iotDeviceState
	opaque  opaqueState
	// Account lifecycle state; see memory_lifecycle.go.
	acctState map[theauth.ULID]theauth.AccountState
	trusted   map[theauth.ULID]theauth.TrustedDevice
}

func New() *Store {
	return &Store{
		users:          map[theauth.ULID]theauth.User{},
		sessions:       map[theauth.ULID]theauth.Session{},
		magicLinks:     map[theauth.ULID]theauth.MagicLink{},
		passwordHashes: map[theauth.ULID]string{},
		resetTokens:    map[theauth.ULID]theauth.PasswordResetToken{},
		oauthAccounts:  map[theauth.ULID]theauth.OAuthAccount{},
		webauthnCreds:  map[theauth.ULID]theauth.WebAuthnCredential{},
		totpSecrets:    map[theauth.ULID]theauth.TOTPSecret{},
		recoveryCodes:  map[theauth.ULID]theauth.RecoveryCode{},
		totpSteps:      map[theauth.ULID]int64{},
	}
}

func (s *Store) CreateUser(_ context.Context, u theauth.User) (theauth.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[u.ID] = u
	return u, nil
}

func (s *Store) UserByEmail(_ context.Context, email string) (*theauth.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.users {
		if u.Email == email {
			cp := u
			return &cp, nil
		}
	}
	return nil, storage.ErrNotFound
}

func (s *Store) UserByID(_ context.Context, id theauth.ULID) (*theauth.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[id]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return &u, nil
}

func (s *Store) MarkEmailVerified(_ context.Context, userID theauth.ULID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[userID]
	if !ok {
		return storage.ErrNotFound
	}
	now := time.Now()
	u.EmailVerifiedAt = &now
	s.users[userID] = u
	return nil
}

func (s *Store) CreateSession(_ context.Context, sess theauth.Session) (theauth.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess.AuthLevel == "" {
		// Mirror the Postgres DDL default.
		sess.AuthLevel = theauth.AuthLevelFull
	}
	s.sessions[sess.ID] = sess
	return sess, nil
}

func (s *Store) SessionByTokenHash(_ context.Context, hash []byte) (*theauth.Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, sess := range s.sessions {
		if bytes.Equal(sess.TokenHash, hash) {
			cp := sess
			return &cp, nil
		}
	}
	return nil, storage.ErrNotFound
}

func (s *Store) SessionByID(_ context.Context, id theauth.ULID) (*theauth.Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.sessions[id]
	if !ok {
		return nil, storage.ErrNotFound
	}
	cp := sess
	return &cp, nil
}

func (s *Store) RevokeSession(_ context.Context, id theauth.ULID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return storage.ErrNotFound
	}
	now := time.Now()
	sess.RevokedAt = &now
	s.sessions[id] = sess
	return nil
}

func (s *Store) RevokeUserSessions(_ context.Context, userID theauth.ULID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for id, sess := range s.sessions {
		if sess.UserID == userID && sess.RevokedAt == nil {
			sess.RevokedAt = &now
			s.sessions[id] = sess
		}
	}
	return nil
}

func (s *Store) CreateMagicLink(_ context.Context, ml theauth.MagicLink) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.magicLinks[ml.ID] = ml
	return nil
}

func (s *Store) ConsumeMagicLink(_ context.Context, hash []byte) (*theauth.MagicLink, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for id, ml := range s.magicLinks {
		if bytes.Equal(ml.TokenHash, hash) && ml.UsedAt == nil && !ml.ExpiresAt.Before(now) {
			ml.UsedAt = &now
			s.magicLinks[id] = ml
			cp := ml
			return &cp, nil
		}
	}
	return nil, storage.ErrNotFound
}

func (s *Store) SetUserPassword(_ context.Context, userID theauth.ULID, passwordHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[userID]; !ok {
		return storage.ErrNotFound
	}
	s.passwordHashes[userID] = passwordHash
	return nil
}

func (s *Store) UserByEmailWithPassword(_ context.Context, email string) (*theauth.User, string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.users {
		if u.Email == email {
			cp := u
			return &cp, s.passwordHashes[u.ID], nil
		}
	}
	return nil, "", storage.ErrNotFound
}

func (s *Store) CreatePasswordResetToken(_ context.Context, t theauth.PasswordResetToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[t.UserID]; !ok {
		return storage.ErrNotFound
	}
	s.resetTokens[t.ID] = t
	return nil
}

func (s *Store) ConsumePasswordResetToken(_ context.Context, hash []byte) (*theauth.PasswordResetToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for id, rt := range s.resetTokens {
		if bytes.Equal(rt.TokenHash, hash) && rt.UsedAt == nil && !rt.ExpiresAt.Before(now) {
			rt.UsedAt = &now
			s.resetTokens[id] = rt
			cp := rt
			return &cp, nil
		}
	}
	return nil, storage.ErrNotFound
}

// UpsertOAuthAccount mirrors the Postgres ON CONFLICT upsert: an existing
// (provider, provider_user_id) row keeps its ID and CreatedAt.
func (s *Store) UpsertOAuthAccount(_ context.Context, a theauth.OAuthAccount) (theauth.OAuthAccount, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for id, existing := range s.oauthAccounts {
		if existing.Provider == a.Provider && existing.ProviderUserID == a.ProviderUserID {
			existing.UserID = a.UserID
			existing.AccessTokenEnc = a.AccessTokenEnc
			existing.RefreshTokenEnc = a.RefreshTokenEnc
			existing.ExpiresAt = a.ExpiresAt
			existing.Scope = a.Scope
			existing.UpdatedAt = now
			s.oauthAccounts[id] = existing
			return existing, nil
		}
	}
	if a.CreatedAt.IsZero() {
		a.CreatedAt = now
	}
	a.UpdatedAt = now
	s.oauthAccounts[a.ID] = a
	return a, nil
}

func (s *Store) OAuthAccountByProviderUserID(_ context.Context, provider, providerUserID string) (*theauth.OAuthAccount, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, a := range s.oauthAccounts {
		if a.Provider == provider && a.ProviderUserID == providerUserID {
			cp := a
			return &cp, nil
		}
	}
	return nil, storage.ErrNotFound
}

// OAuthAccountsByUserID returns every OAuth account row linked to userID.
func (s *Store) OAuthAccountsByUserID(_ context.Context, userID theauth.ULID) ([]theauth.OAuthAccount, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []theauth.OAuthAccount
	for _, a := range s.oauthAccounts {
		if a.UserID == userID {
			out = append(out, a)
		}
	}
	return out, nil
}

// MoveOAuthAccount reassigns a row identified by (provider, providerUserID)
// to newUserID.
func (s *Store) MoveOAuthAccount(_ context.Context, provider, providerUserID string, newUserID theauth.ULID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, a := range s.oauthAccounts {
		if a.Provider == provider && a.ProviderUserID == providerUserID {
			a.UserID = newUserID
			a.UpdatedAt = time.Now()
			s.oauthAccounts[id] = a
			return nil
		}
	}
	return storage.ErrNotFound
}

// DeleteOAuthAccountByProvider removes the row for (userID, provider).
func (s *Store) DeleteOAuthAccountByProvider(_ context.Context, userID theauth.ULID, provider string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, a := range s.oauthAccounts {
		if a.UserID == userID && a.Provider == provider {
			delete(s.oauthAccounts, id)
			return nil
		}
	}
	return storage.ErrNotFound
}

// UserPasswordHashByID returns the stored Argon2id PHC string, or "" when
// the user has no password set.
func (s *Store) UserPasswordHashByID(_ context.Context, userID theauth.ULID) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.passwordHashes[userID], nil
}

// MovePasswordHash copies the Argon2id hash from secondaryID to primaryID
// (overwriting any existing primary hash) then clears secondaryID's hash.
func (s *Store) MovePasswordHash(_ context.Context, primaryID, secondaryID theauth.ULID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	hash, ok := s.passwordHashes[secondaryID]
	if !ok || hash == "" {
		return nil // no-op
	}
	s.passwordHashes[primaryID] = hash
	delete(s.passwordHashes, secondaryID)
	return nil
}

// MoveWebAuthnCredentials reassigns every WebAuthn credential from
// secondaryID to primaryID.
func (s *Store) MoveWebAuthnCredentials(_ context.Context, primaryID, secondaryID theauth.ULID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, cred := range s.webauthnCreds {
		if cred.UserID == secondaryID {
			cred.UserID = primaryID
			s.webauthnCreds[id] = cred
		}
	}
	return nil
}

// MoveTOTPSecret reassigns the TOTP secret. A confirmed primary secret wins,
// so the secondary is dropped rather than clobbering an active factor.
func (s *Store) MoveTOTPSecret(_ context.Context, primaryID, secondaryID theauth.ULID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sec, ok := s.totpSecrets[secondaryID]
	if !ok {
		return nil // no-op
	}
	if _, hasPrimary := s.totpSecrets[primaryID]; !hasPrimary {
		sec.UserID = primaryID
		s.totpSecrets[primaryID] = sec
	}
	delete(s.totpSecrets, secondaryID)
	return nil
}

// CreateSessionWithAuthLevel is CreateSession with an explicit AuthLevel
// (blank defaults to full).
func (s *Store) CreateSessionWithAuthLevel(_ context.Context, sess theauth.Session) (theauth.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess.AuthLevel == "" {
		sess.AuthLevel = theauth.AuthLevelFull
	}
	s.sessions[sess.ID] = sess
	return sess, nil
}

// UpdateSessionAuthLevel rewrites the AuthLevel column, e.g. to promote a
// pending_2fa session after a successful TOTP verify.
func (s *Store) UpdateSessionAuthLevel(_ context.Context, id theauth.ULID, level string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return storage.ErrNotFound
	}
	sess.AuthLevel = level
	s.sessions[id] = sess
	return nil
}

func (s *Store) InsertWebAuthnCredential(_ context.Context, c theauth.WebAuthnCredential) (theauth.WebAuthnCredential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Credential IDs are globally unique, mirroring the Postgres UNIQUE constraint.
	for _, existing := range s.webauthnCreds {
		if bytes.Equal(existing.CredentialID, c.CredentialID) {
			return theauth.WebAuthnCredential{}, storage.ErrNotFound
		}
	}
	s.webauthnCreds[c.ID] = c
	return c, nil
}

func (s *Store) WebAuthnCredentialsByUserID(_ context.Context, userID theauth.ULID) ([]theauth.WebAuthnCredential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []theauth.WebAuthnCredential
	for _, c := range s.webauthnCreds {
		if c.UserID == userID {
			out = append(out, c)
		}
	}
	return out, nil
}

func (s *Store) WebAuthnCredentialByCredentialID(_ context.Context, credentialID []byte) (*theauth.WebAuthnCredential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, c := range s.webauthnCreds {
		if bytes.Equal(c.CredentialID, credentialID) {
			cp := c
			return &cp, nil
		}
	}
	return nil, storage.ErrNotFound
}

func (s *Store) UpdateWebAuthnSignCount(_ context.Context, credentialID []byte, newCount uint32, usedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, c := range s.webauthnCreds {
		if !bytes.Equal(c.CredentialID, credentialID) {
			continue
		}
		// Authenticators without a signature counter send 0; the service layer handles that case.
		if newCount <= c.SignCount {
			return theauth.ErrReplayDetected
		}
		c.SignCount = newCount
		t := usedAt
		c.LastUsedAt = &t
		s.webauthnCreds[id] = c
		return nil
	}
	return storage.ErrNotFound
}

// UpdateWebAuthnBackupFlags records BE/BS flags for trust-on-first-use
// reconciliation of legacy synced passkeys. A missing credential is a no-op.
func (s *Store) UpdateWebAuthnBackupFlags(_ context.Context, credentialID []byte, backupEligible, backupState bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, c := range s.webauthnCreds {
		if !bytes.Equal(c.CredentialID, credentialID) {
			continue
		}
		be, bs := backupEligible, backupState
		c.BackupEligible = &be
		c.BackupState = &bs
		s.webauthnCreds[id] = c
		return nil
	}
	return nil
}

func (s *Store) DeleteWebAuthnCredential(_ context.Context, id theauth.ULID, userID theauth.ULID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.webauthnCreds[id]
	if !ok || c.UserID != userID {
		return storage.ErrNotFound
	}
	delete(s.webauthnCreds, id)
	return nil
}

func (s *Store) RenameWebAuthnCredential(_ context.Context, id, userID theauth.ULID, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.webauthnCreds[id]
	if !ok || c.UserID != userID {
		return storage.ErrNotFound
	}
	c.Name = name
	s.webauthnCreds[id] = c
	return nil
}

func (s *Store) UpsertPendingTOTPSecret(_ context.Context, sec theauth.TOTPSecret) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Preserve a confirmed secret: re-enrollment requires explicit delete.
	if existing, ok := s.totpSecrets[sec.UserID]; ok && existing.ConfirmedAt != nil {
		return nil
	}
	sec.ConfirmedAt = nil
	if sec.CreatedAt.IsZero() {
		sec.CreatedAt = time.Now()
	}
	sec.UpdatedAt = sec.CreatedAt
	s.totpSecrets[sec.UserID] = sec
	return nil
}

func (s *Store) ConfirmTOTPSecret(_ context.Context, userID theauth.ULID, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sec, ok := s.totpSecrets[userID]
	if !ok || sec.ConfirmedAt != nil {
		return storage.ErrNotFound
	}
	t := at
	sec.ConfirmedAt = &t
	sec.UpdatedAt = at
	s.totpSecrets[userID] = sec
	return nil
}

func (s *Store) TOTPSecretByUserID(_ context.Context, userID theauth.ULID) (*theauth.TOTPSecret, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sec, ok := s.totpSecrets[userID]
	if !ok {
		return nil, storage.ErrNotFound
	}
	cp := sec
	return &cp, nil
}

func (s *Store) DeleteTOTPSecret(_ context.Context, userID theauth.ULID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.totpSecrets, userID)
	// Cascade: drop recovery codes when secret goes away.
	for id, rc := range s.recoveryCodes {
		if rc.UserID == userID {
			delete(s.recoveryCodes, id)
		}
	}
	return nil
}

func (s *Store) InsertRecoveryCodes(_ context.Context, codes []theauth.RecoveryCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range codes {
		s.recoveryCodes[c.ID] = c
	}
	return nil
}

func (s *Store) CountUnusedRecoveryCodes(_ context.Context, userID theauth.ULID) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, rc := range s.recoveryCodes {
		if rc.UserID == userID && rc.UsedAt == nil {
			n++
		}
	}
	return n, nil
}

func (s *Store) ReplaceRecoveryCodes(_ context.Context, userID theauth.ULID, codes []theauth.RecoveryCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, rc := range s.recoveryCodes {
		if rc.UserID == userID {
			delete(s.recoveryCodes, id)
		}
	}
	for _, c := range codes {
		s.recoveryCodes[c.ID] = c
	}
	return nil
}

// ConsumeRecoveryCode marks the first unused code that matches in constant time
// as used, returning ErrNotFound when none match.
func (s *Store) ConsumeRecoveryCode(_ context.Context, userID theauth.ULID, code string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, rc := range s.recoveryCodes {
		if rc.UserID != userID || rc.UsedAt != nil {
			continue
		}
		if !crypto.VerifyRecoveryCode(rc.CodeHash, code) {
			continue
		}
		t := at
		rc.UsedAt = &t
		s.recoveryCodes[id] = rc
		return nil
	}
	return storage.ErrNotFound
}
