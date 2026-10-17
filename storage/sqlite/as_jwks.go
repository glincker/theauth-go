package sqlite

import (
	"context"
	"database/sql"
	"time"

	"github.com/glincker/theauth-go/v2"
)

// as_jwks.go: authorization server signing keys over migration 0024.

const asJWKSCols = `kid, alg, use_, public_jwk, private_enc, state, created_at, promoted_at, retired_at`

// InsertJWKSKey implements theauth.OAuthServerStorage. A duplicate kid, or a
// second current key for the same algorithm, is rejected by the schema.
func (s *Store) InsertJWKSKey(ctx context.Context, k theauth.JWKSKey) error {
	return asInsertJWKSKey(ctx, s.db, s.q, k, time.Now())
}

func asInsertJWKSKey(ctx context.Context, db DBTX, q func(string) string, k theauth.JWKSKey, now time.Time) error {
	created := k.CreatedAt
	if created.IsZero() {
		created = now
	}
	_, err := db.ExecContext(ctx, q(`
INSERT INTO theauth_jwks_keys (`+asJWKSCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		k.KID, k.Alg, asDefault(k.Use, "sig"), nonNilBytes(k.PublicJWK), nonNilBytes(k.PrivateEnc), k.State,
		toMicro(created), toNullMicro(k.PromotedAt), toNullMicro(k.RetiredAt))
	return wrap("insert jwks key", err)
}

func asScanJWKS(r scanner) (theauth.JWKSKey, error) {
	var (
		k                 theauth.JWKSKey
		created           int64
		promoted, retired sql.NullInt64
	)
	if err := r.Scan(&k.KID, &k.Alg, &k.Use, &k.PublicJWK, &k.PrivateEnc, &k.State, &created, &promoted, &retired); err != nil {
		return theauth.JWKSKey{}, err
	}
	k.CreatedAt = fromMicro(created)
	k.PromotedAt = fromNullMicro(promoted)
	k.RetiredAt = fromNullMicro(retired)
	return k, nil
}

func (s *Store) JWKSKeyByKID(ctx context.Context, kid string) (*theauth.JWKSKey, error) {
	k, err := asScanJWKS(s.db.QueryRowContext(ctx, s.q(
		`SELECT `+asJWKSCols+` FROM theauth_jwks_keys WHERE kid = ?`), kid))
	if err != nil {
		return nil, notFoundOr("jwks key by kid", err)
	}
	return &k, nil
}

// JWKSKeysAll implements theauth.OAuthServerStorage, oldest key first.
func (s *Store) JWKSKeysAll(ctx context.Context) ([]theauth.JWKSKey, error) {
	rows, err := s.db.QueryContext(ctx, s.q(
		`SELECT `+asJWKSCols+` FROM theauth_jwks_keys ORDER BY created_at ASC, kid ASC`))
	if err != nil {
		return nil, wrap("list jwks keys", err)
	}
	defer func() { _ = rows.Close() }()
	var out []theauth.JWKSKey
	for rows.Next() {
		k, err := asScanJWKS(rows)
		if err != nil {
			return nil, wrap("list jwks keys", err)
		}
		out = append(out, k)
	}
	return out, wrap("list jwks keys", rows.Err())
}

// UpdateJWKSKeyState implements theauth.OAuthServerStorage, stamping promoted_at or retired_at on
// transition. An unknown kid is ErrStorageNotFound.
func (s *Store) UpdateJWKSKeyState(ctx context.Context, kid, state string, at time.Time) error {
	var (
		res sql.Result
		err error
	)
	switch state {
	case theauth.JWKSStateCurrent:
		res, err = s.db.ExecContext(ctx, s.q(`UPDATE theauth_jwks_keys SET state = ?, promoted_at = ? WHERE kid = ?`),
			state, toMicro(at), kid)
	case theauth.JWKSStateRetired:
		res, err = s.db.ExecContext(ctx, s.q(`UPDATE theauth_jwks_keys SET state = ?, retired_at = ? WHERE kid = ?`),
			state, toMicro(at), kid)
	default:
		res, err = s.db.ExecContext(ctx, s.q(`UPDATE theauth_jwks_keys SET state = ? WHERE kid = ?`), state, kid)
	}
	if err != nil {
		return wrap("update jwks key state", err)
	}
	return requireRows("update jwks key state", res)
}

// AtomicRotateJWKS implements as.JWKSAtomicRotator in one write-first transaction, so concurrent
// rotations serialize. Order matters for the one-current-per-algorithm index: retire, demote,
// promote, then insert. Unknown kids roll back.
func (s *Store) AtomicRotateJWKS(ctx context.Context, retireKIDs []string, demoteKID, promoteKID string, freshKey theauth.JWKSKey, now time.Time) error {
	return s.inTx(ctx, "rotate jwks", func(tx DBTX) error {
		at := toMicro(now)
		for _, kid := range retireKIDs {
			if _, err := tx.ExecContext(ctx, s.q(
				`UPDATE theauth_jwks_keys SET state = 'retired', retired_at = ? WHERE kid = ?`), at, kid); err != nil {
				return err
			}
		}
		res, err := tx.ExecContext(ctx, s.q(`UPDATE theauth_jwks_keys SET state = 'previous' WHERE kid = ?`), demoteKID)
		if err != nil {
			return err
		}
		if err := requireRows("demote jwks key", res); err != nil {
			return err
		}
		res, err = tx.ExecContext(ctx, s.q(
			`UPDATE theauth_jwks_keys SET state = 'current', promoted_at = ? WHERE kid = ?`), at, promoteKID)
		if err != nil {
			return err
		}
		if err := requireRows("promote jwks key", res); err != nil {
			return err
		}
		return asInsertJWKSKey(ctx, tx, s.q, freshKey, now)
	})
}
