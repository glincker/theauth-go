// Package postgres provides a Postgres-backed storage.Storage implementation
// built on top of sqlc-generated queries and pgx/v5.
package postgres

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/crypto"
	"github.com/glincker/theauth-go/storage"
	sqlcgen "github.com/glincker/theauth-go/storage/postgres/sqlc"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Compile-time interface assertion: Store must satisfy storage.Storage.
var _ storage.Storage = (*Store)(nil)

// Store is the Postgres-backed storage adapter.
type Store struct {
	pool *pgxpool.Pool
	q    *sqlcgen.Queries
}

// New constructs a Store using the given pgxpool.Pool.
func New(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool, q: sqlcgen.New(pool)}
}

// ---------- type mapping helpers ----------

func ulidToPgUUID(id theauth.ULID) pgtype.UUID {
	return pgtype.UUID{Bytes: [16]byte(id), Valid: true}
}

func pgUUIDToULID(u pgtype.UUID) theauth.ULID {
	return theauth.ULID(u.Bytes)
}

func tsToTimePtr(ts pgtype.Timestamptz) *time.Time {
	if !ts.Valid {
		return nil
	}
	t := ts.Time
	return &t
}

func timeToTs(t time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: t, Valid: true}
}

func tsToTime(ts pgtype.Timestamptz) time.Time {
	return ts.Time
}

// ipStrToPg returns a pointer to a parsed netip.Addr, or nil if the input is
// empty or unparseable. Bad IP strings are silently dropped (v0.1 behavior:
// don't fail the whole call on a malformed UA-supplied IP).
func ipStrToPg(ip string) *netip.Addr {
	if ip == "" {
		return nil
	}
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return nil
	}
	return &a
}

func pgIPToStr(p *netip.Addr) string {
	if p == nil {
		return ""
	}
	return p.String()
}

// ---------- row -> domain mappers ----------

func rowToUser(r sqlcgen.User) theauth.User {
	return theauth.User{
		ID:              pgUUIDToULID(r.ID),
		Email:           r.Email,
		EmailVerifiedAt: tsToTimePtr(r.EmailVerifiedAt),
		Name:            r.Name,
		AvatarURL:       r.AvatarUrl,
		CreatedAt:       tsToTime(r.CreatedAt),
		UpdatedAt:       tsToTime(r.UpdatedAt),
	}
}

func rowToSession(r sqlcgen.Session) theauth.Session {
	return theauth.Session{
		ID:        pgUUIDToULID(r.ID),
		UserID:    pgUUIDToULID(r.UserID),
		TokenHash: r.TokenHash,
		UserAgent: r.UserAgent,
		IP:        pgIPToStr(r.Ip),
		CreatedAt: tsToTime(r.CreatedAt),
		ExpiresAt: tsToTime(r.ExpiresAt),
		RevokedAt: tsToTimePtr(r.RevokedAt),
		AuthLevel: r.AuthLevel,
	}
}

func rowToMagicLink(r sqlcgen.MagicLink) theauth.MagicLink {
	return theauth.MagicLink{
		ID:        pgUUIDToULID(r.ID),
		Email:     r.Email,
		TokenHash: r.TokenHash,
		ExpiresAt: tsToTime(r.ExpiresAt),
		UsedAt:    tsToTimePtr(r.UsedAt),
		CreatedAt: tsToTime(r.CreatedAt),
	}
}

func rowToResetToken(r sqlcgen.PasswordResetToken) theauth.PasswordResetToken {
	return theauth.PasswordResetToken{
		ID:        pgUUIDToULID(r.ID),
		UserID:    pgUUIDToULID(r.UserID),
		TokenHash: r.TokenHash,
		ExpiresAt: tsToTime(r.ExpiresAt),
		UsedAt:    tsToTimePtr(r.UsedAt),
		CreatedAt: tsToTime(r.CreatedAt),
	}
}

func rowToOAuthAccount(r sqlcgen.OauthAccount) theauth.OAuthAccount {
	return theauth.OAuthAccount{
		ID:              pgUUIDToULID(r.ID),
		UserID:          pgUUIDToULID(r.UserID),
		Provider:        r.Provider,
		ProviderUserID:  r.ProviderUserID,
		AccessTokenEnc:  r.AccessTokenEnc,
		RefreshTokenEnc: r.RefreshTokenEnc,
		ExpiresAt:       tsToTimePtr(r.ExpiresAt),
		Scope:           r.Scope,
		CreatedAt:       tsToTime(r.CreatedAt),
		UpdatedAt:       tsToTime(r.UpdatedAt),
	}
}

// timePtrToTs returns a nullable pgtype.Timestamptz from an optional time.
func timePtrToTs(t *time.Time) pgtype.Timestamptz {
	if t == nil {
		return pgtype.Timestamptz{Valid: false}
	}
	return pgtype.Timestamptz{Time: *t, Valid: true}
}

// ---------- Users ----------

func (s *Store) CreateUser(ctx context.Context, u theauth.User) (theauth.User, error) {
	row, err := s.q.CreateUser(ctx, sqlcgen.CreateUserParams{
		ID:        ulidToPgUUID(u.ID),
		Email:     u.Email,
		Name:      u.Name,
		AvatarUrl: u.AvatarURL,
		CreatedAt: timeToTs(u.CreatedAt),
		UpdatedAt: timeToTs(u.UpdatedAt),
	})
	if err != nil {
		return theauth.User{}, err
	}
	return rowToUser(row), nil
}

func (s *Store) UserByEmail(ctx context.Context, email string) (*theauth.User, error) {
	row, err := s.q.UserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, storage.ErrNotFound
		}
		return nil, err
	}
	u := rowToUser(row)
	return &u, nil
}

func (s *Store) UserByID(ctx context.Context, id theauth.ULID) (*theauth.User, error) {
	row, err := s.q.UserByID(ctx, ulidToPgUUID(id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, storage.ErrNotFound
		}
		return nil, err
	}
	u := rowToUser(row)
	return &u, nil
}

func (s *Store) MarkEmailVerified(ctx context.Context, userID theauth.ULID) error {
	if err := s.q.MarkEmailVerified(ctx, ulidToPgUUID(userID)); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return storage.ErrNotFound
		}
		return err
	}
	return nil
}

// ---------- Sessions ----------

func (s *Store) CreateSession(ctx context.Context, sess theauth.Session) (theauth.Session, error) {
	row, err := s.q.CreateSession(ctx, sqlcgen.CreateSessionParams{
		ID:        ulidToPgUUID(sess.ID),
		UserID:    ulidToPgUUID(sess.UserID),
		TokenHash: sess.TokenHash,
		UserAgent: sess.UserAgent,
		Ip:        ipStrToPg(sess.IP),
		CreatedAt: timeToTs(sess.CreatedAt),
		ExpiresAt: timeToTs(sess.ExpiresAt),
	})
	if err != nil {
		return theauth.Session{}, err
	}
	return rowToSession(row), nil
}

func (s *Store) SessionByTokenHash(ctx context.Context, hash []byte) (*theauth.Session, error) {
	row, err := s.q.SessionByTokenHash(ctx, hash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, storage.ErrNotFound
		}
		return nil, err
	}
	sess := rowToSession(row)
	return &sess, nil
}

func (s *Store) RevokeSession(ctx context.Context, id theauth.ULID) error {
	if err := s.q.RevokeSession(ctx, ulidToPgUUID(id)); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return storage.ErrNotFound
		}
		return err
	}
	return nil
}

func (s *Store) RevokeUserSessions(ctx context.Context, userID theauth.ULID) error {
	if err := s.q.RevokeUserSessions(ctx, ulidToPgUUID(userID)); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return storage.ErrNotFound
		}
		return err
	}
	return nil
}

// ---------- Magic links ----------

func (s *Store) CreateMagicLink(ctx context.Context, ml theauth.MagicLink) error {
	return s.q.CreateMagicLink(ctx, sqlcgen.CreateMagicLinkParams{
		ID:        ulidToPgUUID(ml.ID),
		Email:     ml.Email,
		TokenHash: ml.TokenHash,
		ExpiresAt: timeToTs(ml.ExpiresAt),
		CreatedAt: timeToTs(ml.CreatedAt),
	})
}

func (s *Store) ConsumeMagicLink(ctx context.Context, tokenHash []byte) (*theauth.MagicLink, error) {
	row, err := s.q.ConsumeMagicLink(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, storage.ErrNotFound
		}
		return nil, err
	}
	ml := rowToMagicLink(row)
	return &ml, nil
}

// ---------- Password credentials (v0.2) ----------

func (s *Store) SetUserPassword(ctx context.Context, userID theauth.ULID, passwordHash string) error {
	ph := passwordHash
	if err := s.q.SetUserPassword(ctx, sqlcgen.SetUserPasswordParams{
		ID:           ulidToPgUUID(userID),
		PasswordHash: &ph,
	}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return storage.ErrNotFound
		}
		return err
	}
	return nil
}

func (s *Store) UserByEmailWithPassword(ctx context.Context, email string) (*theauth.User, string, error) {
	row, err := s.q.UserByEmailWithPassword(ctx, email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, "", storage.ErrNotFound
		}
		return nil, "", err
	}
	u := theauth.User{
		ID:              pgUUIDToULID(row.ID),
		Email:           row.Email,
		EmailVerifiedAt: tsToTimePtr(row.EmailVerifiedAt),
		Name:            row.Name,
		AvatarURL:       row.AvatarUrl,
		CreatedAt:       tsToTime(row.CreatedAt),
		UpdatedAt:       tsToTime(row.UpdatedAt),
	}
	return &u, row.PasswordHash, nil
}

func (s *Store) CreatePasswordResetToken(ctx context.Context, t theauth.PasswordResetToken) error {
	return s.q.CreatePasswordResetToken(ctx, sqlcgen.CreatePasswordResetTokenParams{
		ID:        ulidToPgUUID(t.ID),
		UserID:    ulidToPgUUID(t.UserID),
		TokenHash: t.TokenHash,
		ExpiresAt: timeToTs(t.ExpiresAt),
		CreatedAt: timeToTs(t.CreatedAt),
	})
}

func (s *Store) ConsumePasswordResetToken(ctx context.Context, tokenHash []byte) (*theauth.PasswordResetToken, error) {
	row, err := s.q.ConsumePasswordResetToken(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, storage.ErrNotFound
		}
		return nil, err
	}
	rt := rowToResetToken(row)
	return &rt, nil
}

// ---------- OAuth accounts (v0.3) ----------

func (s *Store) UpsertOAuthAccount(ctx context.Context, a theauth.OAuthAccount) (theauth.OAuthAccount, error) {
	row, err := s.q.UpsertOAuthAccount(ctx, sqlcgen.UpsertOAuthAccountParams{
		ID:              ulidToPgUUID(a.ID),
		UserID:          ulidToPgUUID(a.UserID),
		Provider:        a.Provider,
		ProviderUserID:  a.ProviderUserID,
		AccessTokenEnc:  a.AccessTokenEnc,
		RefreshTokenEnc: a.RefreshTokenEnc,
		ExpiresAt:       timePtrToTs(a.ExpiresAt),
		Scope:           a.Scope,
		CreatedAt:       timeToTs(a.CreatedAt),
		UpdatedAt:       timeToTs(a.UpdatedAt),
	})
	if err != nil {
		return theauth.OAuthAccount{}, err
	}
	return rowToOAuthAccount(row), nil
}

func (s *Store) OAuthAccountByProviderUserID(ctx context.Context, provider, providerUserID string) (*theauth.OAuthAccount, error) {
	row, err := s.q.OAuthAccountByProviderUserID(ctx, sqlcgen.OAuthAccountByProviderUserIDParams{
		Provider:       provider,
		ProviderUserID: providerUserID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, storage.ErrNotFound
		}
		return nil, err
	}
	acct := rowToOAuthAccount(row)
	return &acct, nil
}

// ---------- Sessions (v0.5 step-up) ----------

func (s *Store) CreateSessionWithAuthLevel(ctx context.Context, sess theauth.Session) (theauth.Session, error) {
	level := sess.AuthLevel
	if level == "" {
		level = theauth.AuthLevelFull
	}
	row, err := s.q.CreateSessionWithAuthLevel(ctx, sqlcgen.CreateSessionWithAuthLevelParams{
		ID:        ulidToPgUUID(sess.ID),
		UserID:    ulidToPgUUID(sess.UserID),
		TokenHash: sess.TokenHash,
		UserAgent: sess.UserAgent,
		Ip:        ipStrToPg(sess.IP),
		CreatedAt: timeToTs(sess.CreatedAt),
		ExpiresAt: timeToTs(sess.ExpiresAt),
		AuthLevel: level,
	})
	if err != nil {
		return theauth.Session{}, err
	}
	return rowToSession(row), nil
}

func (s *Store) UpdateSessionAuthLevel(ctx context.Context, id theauth.ULID, level string) error {
	if err := s.q.UpdateSessionAuthLevel(ctx, sqlcgen.UpdateSessionAuthLevelParams{
		ID:        ulidToPgUUID(id),
		AuthLevel: level,
	}); err != nil {
		return err
	}
	return nil
}

// ---------- WebAuthn credentials (v0.5) ----------

// signCountInt64ToUint32 narrows a Postgres bigint column to the uint32 that
// the WebAuthn spec requires. Values outside the uint32 range (which the
// spec forbids; authenticators MUST emit a 32-bit counter) are clamped to
// the maximum to keep replay detection safe-by-default rather than wrapping.
func signCountInt64ToUint32(v int64) uint32 {
	if v < 0 {
		return 0
	}
	const maxU32 = int64(^uint32(0))
	if v > maxU32 {
		return ^uint32(0)
	}
	return uint32(v)
}

func rowToWebAuthnCredential(r sqlcgen.WebauthnCredential) theauth.WebAuthnCredential {
	return theauth.WebAuthnCredential{
		ID:           pgUUIDToULID(r.ID),
		UserID:       pgUUIDToULID(r.UserID),
		CredentialID: r.CredentialID,
		PublicKey:    r.PublicKey,
		SignCount:    signCountInt64ToUint32(r.SignCount),
		Transports:   r.Transports,
		AAGUID:       r.Aaguid,
		Name:         r.Name,
		CreatedAt:    tsToTime(r.CreatedAt),
		LastUsedAt:   tsToTimePtr(r.LastUsedAt),
	}
}

func (s *Store) InsertWebAuthnCredential(ctx context.Context, c theauth.WebAuthnCredential) (theauth.WebAuthnCredential, error) {
	row, err := s.q.InsertWebAuthnCredential(ctx, sqlcgen.InsertWebAuthnCredentialParams{
		ID:           ulidToPgUUID(c.ID),
		UserID:       ulidToPgUUID(c.UserID),
		CredentialID: c.CredentialID,
		PublicKey:    c.PublicKey,
		SignCount:    int64(c.SignCount),
		Transports:   c.Transports,
		Aaguid:       c.AAGUID,
		Name:         c.Name,
		CreatedAt:    timeToTs(c.CreatedAt),
		LastUsedAt:   timePtrToTs(c.LastUsedAt),
	})
	if err != nil {
		return theauth.WebAuthnCredential{}, err
	}
	return rowToWebAuthnCredential(row), nil
}

func (s *Store) WebAuthnCredentialsByUserID(ctx context.Context, userID theauth.ULID) ([]theauth.WebAuthnCredential, error) {
	rows, err := s.q.WebAuthnCredentialsByUserID(ctx, ulidToPgUUID(userID))
	if err != nil {
		return nil, err
	}
	out := make([]theauth.WebAuthnCredential, 0, len(rows))
	for _, r := range rows {
		out = append(out, rowToWebAuthnCredential(r))
	}
	return out, nil
}

func (s *Store) WebAuthnCredentialByCredentialID(ctx context.Context, credentialID []byte) (*theauth.WebAuthnCredential, error) {
	row, err := s.q.WebAuthnCredentialByCredentialID(ctx, credentialID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, storage.ErrNotFound
		}
		return nil, err
	}
	c := rowToWebAuthnCredential(row)
	return &c, nil
}

// UpdateWebAuthnSignCount executes the strictly-greater UPDATE; zero rows
// affected with the credential present means the supplied count was not
// strictly greater than the stored one, which is the WebAuthn replay
// signal. We disambiguate "no such credential" from "replay" via a follow
// up SELECT only when the UPDATE is a miss, to keep the happy path single
// round-trip.
func (s *Store) UpdateWebAuthnSignCount(ctx context.Context, credentialID []byte, newCount uint32, usedAt time.Time) error {
	affected, err := s.q.UpdateWebAuthnSignCount(ctx, sqlcgen.UpdateWebAuthnSignCountParams{
		CredentialID: credentialID,
		SignCount:    int64(newCount),
		LastUsedAt:   timeToTs(usedAt),
	})
	if err != nil {
		return err
	}
	if affected == 1 {
		return nil
	}
	// Zero rows: either the credential is gone or sign_count didn't move
	// forward. A targeted lookup distinguishes the two without leaking any
	// information beyond what the caller already sees.
	if _, lookupErr := s.q.WebAuthnCredentialByCredentialID(ctx, credentialID); errors.Is(lookupErr, pgx.ErrNoRows) {
		return storage.ErrNotFound
	}
	return theauth.ErrReplayDetected
}

func (s *Store) DeleteWebAuthnCredential(ctx context.Context, id theauth.ULID, userID theauth.ULID) error {
	affected, err := s.q.DeleteWebAuthnCredential(ctx, sqlcgen.DeleteWebAuthnCredentialParams{
		ID:     ulidToPgUUID(id),
		UserID: ulidToPgUUID(userID),
	})
	if err != nil {
		return err
	}
	if affected == 0 {
		return storage.ErrNotFound
	}
	return nil
}

// ---------- TOTP secrets (v0.5) ----------

func rowToTOTPSecret(r sqlcgen.TotpSecret) theauth.TOTPSecret {
	return theauth.TOTPSecret{
		UserID:      pgUUIDToULID(r.UserID),
		SecretEnc:   r.SecretEnc,
		ConfirmedAt: tsToTimePtr(r.ConfirmedAt),
		CreatedAt:   tsToTime(r.CreatedAt),
		UpdatedAt:   tsToTime(r.UpdatedAt),
	}
}

func (s *Store) UpsertPendingTOTPSecret(ctx context.Context, sec theauth.TOTPSecret) error {
	created := sec.CreatedAt
	if created.IsZero() {
		created = time.Now()
	}
	return s.q.UpsertPendingTOTPSecret(ctx, sqlcgen.UpsertPendingTOTPSecretParams{
		UserID:    ulidToPgUUID(sec.UserID),
		SecretEnc: sec.SecretEnc,
		CreatedAt: timeToTs(created),
	})
}

func (s *Store) ConfirmTOTPSecret(ctx context.Context, userID theauth.ULID, at time.Time) error {
	affected, err := s.q.ConfirmTOTPSecret(ctx, sqlcgen.ConfirmTOTPSecretParams{
		UserID:      ulidToPgUUID(userID),
		ConfirmedAt: timeToTs(at),
	})
	if err != nil {
		return err
	}
	if affected == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func (s *Store) TOTPSecretByUserID(ctx context.Context, userID theauth.ULID) (*theauth.TOTPSecret, error) {
	row, err := s.q.TOTPSecretByUserID(ctx, ulidToPgUUID(userID))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, storage.ErrNotFound
		}
		return nil, err
	}
	sec := rowToTOTPSecret(row)
	return &sec, nil
}

func (s *Store) DeleteTOTPSecret(ctx context.Context, userID theauth.ULID) error {
	// FK is ON DELETE CASCADE so dropping totp_secrets via the user row
	// would cascade, but here we delete by user_id directly and also
	// clear recovery codes to keep the in-memory and postgres adapters
	// observably identical.
	if err := s.q.DeleteRecoveryCodesByUserID(ctx, ulidToPgUUID(userID)); err != nil {
		return err
	}
	return s.q.DeleteTOTPSecret(ctx, ulidToPgUUID(userID))
}

// ---------- Recovery codes (v0.5) ----------

func (s *Store) InsertRecoveryCodes(ctx context.Context, codes []theauth.RecoveryCode) error {
	for _, c := range codes {
		if err := s.q.InsertRecoveryCode(ctx, sqlcgen.InsertRecoveryCodeParams{
			ID:        ulidToPgUUID(c.ID),
			UserID:    ulidToPgUUID(c.UserID),
			CodeHash:  c.CodeHash,
			CreatedAt: timeToTs(c.CreatedAt),
		}); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) ConsumeRecoveryCode(ctx context.Context, userID theauth.ULID, code string, at time.Time) error {
	rows, err := s.q.RecoveryCodesByUserID(ctx, ulidToPgUUID(userID))
	if err != nil {
		return err
	}
	for _, r := range rows {
		if !crypto.VerifyRecoveryCode(r.CodeHash, code) {
			continue
		}
		affected, err := s.q.ConsumeRecoveryCodeByID(ctx, sqlcgen.ConsumeRecoveryCodeByIDParams{
			ID:     r.ID,
			UsedAt: timeToTs(at),
		})
		if err != nil {
			return err
		}
		if affected == 0 {
			// Lost a race to another concurrent verify; keep walking the
			// remaining unused codes in case there is another match.
			continue
		}
		return nil
	}
	return storage.ErrNotFound
}
