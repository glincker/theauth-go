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

func timePtrToTs(t *time.Time) pgtype.Timestamptz {
	if t == nil {
		return pgtype.Timestamptz{Valid: false}
	}
	return pgtype.Timestamptz{Time: *t, Valid: true}
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
	out := rowToUser(row)
	// Preserve caller-supplied EmailVerifiedAt if the column was filled in by
	// other means; the INSERT does not set it, so the row reflects DB state.
	if u.EmailVerifiedAt != nil && out.EmailVerifiedAt == nil {
		out.EmailVerifiedAt = u.EmailVerifiedAt
	}
	return out, nil
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

// Silence unused-import warnings for timePtrToTs when no caller is using it
// yet (kept for future Update methods).
var _ = timePtrToTs
