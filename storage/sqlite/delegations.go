package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/glincker/theauth-go/v2"
)

// delegationStorage is the delegation subset of theauth.OAuthServerStorage.
type delegationStorage interface {
	InsertDelegationGrant(ctx context.Context, g theauth.DelegationGrant) (theauth.DelegationGrant, error)
	DelegationGrantByID(ctx context.Context, id theauth.ULID) (*theauth.DelegationGrant, error)
	DelegationGrantByUserAgentResource(ctx context.Context, userID, agentID theauth.ULID, resource string) (*theauth.DelegationGrant, error)
	DelegationGrantsByUserID(ctx context.Context, userID theauth.ULID) ([]theauth.DelegationGrant, error)
	DelegationGrantsByAgentID(ctx context.Context, agentID theauth.ULID) ([]theauth.DelegationGrant, error)
	RevokeDelegationGrant(ctx context.Context, id theauth.ULID, at time.Time, reason string) error
}

var _ delegationStorage = (*Store)(nil)

const grantCols = `id, user_id, agent_id, organization_id, scope_grant, resource, max_duration_seconds, created_at, expires_at, revoked_at, revocation_note`

func scanGrant(r scanner) (theauth.DelegationGrant, error) {
	var (
		id, user, agent, scope, resource, note string
		org                                    sql.NullString
		maxDur, created                        int64
		expires, revoked                       sql.NullInt64
	)
	if err := r.Scan(&id, &user, &agent, &org, &scope, &resource, &maxDur, &created, &expires, &revoked, &note); err != nil {
		return theauth.DelegationGrant{}, err
	}
	gid, err := parseID(id)
	if err != nil {
		return theauth.DelegationGrant{}, err
	}
	uid, err := parseID(user)
	if err != nil {
		return theauth.DelegationGrant{}, err
	}
	aid, err := parseID(agent)
	if err != nil {
		return theauth.DelegationGrant{}, err
	}
	orgID, err := parseIDPtr(org)
	if err != nil {
		return theauth.DelegationGrant{}, err
	}
	sc, err := decodeList(scope)
	if err != nil {
		return theauth.DelegationGrant{}, err
	}
	return theauth.DelegationGrant{
		ID: gid, UserID: uid, AgentID: aid, OrganizationID: orgID, Scope: sc, Resource: resource,
		MaxDurationSeconds: int(maxDur), CreatedAt: fromMicro(created), ExpiresAt: fromNullMicro(expires),
		RevokedAt: fromNullMicro(revoked), RevocationNote: note,
	}, nil
}

// InsertDelegationGrant allows at most one live grant per (user, agent, resource). A second live
// insert or a duplicate id returns ErrStorageNotFound; a revoked grant frees the tuple.
func (s *Store) InsertDelegationGrant(ctx context.Context, g theauth.DelegationGrant) (theauth.DelegationGrant, error) {
	g.CreatedAt = orNow(g.CreatedAt).UTC().Truncate(time.Microsecond)
	scope, err := encodeList(g.Scope)
	if err != nil {
		return theauth.DelegationGrant{}, err
	}
	_, err = s.db.ExecContext(ctx, s.q(`
INSERT INTO theauth_delegation_grants (`+grantCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		idStr(g.ID), idStr(g.UserID), idStr(g.AgentID), idPtrStr(g.OrganizationID), scope, g.Resource,
		int64(g.MaxDurationSeconds), toMicro(g.CreatedAt), toNullMicro(g.ExpiresAt), toNullMicro(g.RevokedAt), g.RevocationNote)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return theauth.DelegationGrant{}, fmt.Errorf("theauth sqlite: insert delegation grant: live grant exists: %w", theauth.ErrStorageNotFound)
		}
		return theauth.DelegationGrant{}, wrap("insert delegation grant", err)
	}
	return g, nil
}

// DelegationGrantByID returns the grant or ErrStorageNotFound.
func (s *Store) DelegationGrantByID(ctx context.Context, id theauth.ULID) (*theauth.DelegationGrant, error) {
	g, err := scanGrant(s.db.QueryRowContext(ctx, s.q(`SELECT `+grantCols+` FROM theauth_delegation_grants WHERE id = ?`), idStr(id)))
	if err != nil {
		return nil, notFoundOr("delegation grant by id", err)
	}
	return &g, nil
}

// DelegationGrantByUserAgentResource returns the live grant for the tuple, or
// the most recent revoked one when no live grant exists.
func (s *Store) DelegationGrantByUserAgentResource(ctx context.Context, userID, agentID theauth.ULID, resource string) (*theauth.DelegationGrant, error) {
	g, err := scanGrant(s.db.QueryRowContext(ctx, s.q(`
SELECT `+grantCols+` FROM theauth_delegation_grants
WHERE user_id = ? AND agent_id = ? AND resource = ?
ORDER BY (revoked_at IS NULL) DESC, created_at DESC, id DESC LIMIT 1`), idStr(userID), idStr(agentID), resource))
	if err != nil {
		return nil, notFoundOr("delegation grant by tuple", err)
	}
	return &g, nil
}

// DelegationGrantsByUserID lists every grant of the user, oldest first.
func (s *Store) DelegationGrantsByUserID(ctx context.Context, userID theauth.ULID) ([]theauth.DelegationGrant, error) {
	return s.queryGrants(ctx, "delegation grants by user", `user_id = ?`, idStr(userID))
}

// DelegationGrantsByAgentID lists every grant held by the agent, oldest first.
func (s *Store) DelegationGrantsByAgentID(ctx context.Context, agentID theauth.ULID) ([]theauth.DelegationGrant, error) {
	return s.queryGrants(ctx, "delegation grants by agent", `agent_id = ?`, idStr(agentID))
}

func (s *Store) queryGrants(ctx context.Context, op, where string, arg string) ([]theauth.DelegationGrant, error) {
	rows, err := s.db.QueryContext(ctx, s.q(`SELECT `+grantCols+` FROM theauth_delegation_grants WHERE `+where+` ORDER BY created_at ASC, id ASC`), arg)
	if err != nil {
		return nil, wrap(op, err)
	}
	defer func() { _ = rows.Close() }()
	var out []theauth.DelegationGrant
	for rows.Next() {
		g, err := scanGrant(rows)
		if err != nil {
			return nil, wrap(op, err)
		}
		out = append(out, g)
	}
	return out, wrap(op, rows.Err())
}

// RevokeDelegationGrant is conditional on revoked_at IS NULL, so exactly one concurrent caller
// wins and keeps its reason and time. Later calls return ErrStorageNotFound; internal/delegation
// relies on that to emit one audit event.
func (s *Store) RevokeDelegationGrant(ctx context.Context, id theauth.ULID, at time.Time, reason string) error {
	res, err := s.db.ExecContext(ctx, s.q(`UPDATE theauth_delegation_grants SET revoked_at = ?, revocation_note = ? WHERE id = ? AND revoked_at IS NULL`),
		toMicro(at), reason, idStr(id))
	if err != nil {
		return wrap("revoke delegation grant", err)
	}
	return requireRows("revoke delegation grant", res)
}
