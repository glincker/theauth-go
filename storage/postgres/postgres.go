// Package postgres provides a Postgres-backed storage.Storage implementation
// built on top of sqlc-generated queries and pgx/v5.
package postgres

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/glincker/theauth-go"
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
