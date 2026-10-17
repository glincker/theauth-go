package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/glincker/theauth-go/v2"
)

// agentStorage is the agent subset of theauth.OAuthServerStorage; the assertion below
// fails the build on drift.
type agentStorage interface {
	InsertAgent(ctx context.Context, a theauth.Agent) (theauth.Agent, error)
	AgentByID(ctx context.Context, id theauth.ULID) (*theauth.Agent, error)
	AgentByClientID(ctx context.Context, clientID string) (*theauth.Agent, error)
	AgentsByOwner(ctx context.Context, owner theauth.AgentOwner) ([]theauth.Agent, error)
	UpdateAgentStatus(ctx context.Context, id theauth.ULID, status string, at time.Time) error
	UpdateAgentLastActive(ctx context.Context, id theauth.ULID, at time.Time) error
	InsertAgentCredential(ctx context.Context, c theauth.AgentCredential) error
	AgentCredentialsByAgentID(ctx context.Context, agentID theauth.ULID) ([]theauth.AgentCredential, error)
	RevokeAgentCredential(ctx context.Context, id theauth.ULID, at time.Time) error
	UpdateAgentCredentialLastUsed(ctx context.Context, id theauth.ULID, at time.Time) error
}

var _ agentStorage = (*Store)(nil)

const agentCols = `id, owner_user_id, organization_id, name, description, status, client_id, scope_grant, created_at, last_active_at`

const agentCredCols = `id, agent_id, kind, value_enc, created_at, expires_at, last_used_at, revoked_at`

func scanAgentRow(r scanner) (theauth.Agent, error) {
	var (
		id, name, desc, status, clientID, scope string
		owner, org                              sql.NullString
		created                                 int64
		lastActive                              sql.NullInt64
	)
	if err := r.Scan(&id, &owner, &org, &name, &desc, &status, &clientID, &scope, &created, &lastActive); err != nil {
		return theauth.Agent{}, err
	}
	aid, err := parseID(id)
	if err != nil {
		return theauth.Agent{}, err
	}
	ownerID, err := parseIDPtr(owner)
	if err != nil {
		return theauth.Agent{}, err
	}
	orgID, err := parseIDPtr(org)
	if err != nil {
		return theauth.Agent{}, err
	}
	sc, err := decodeList(scope)
	if err != nil {
		return theauth.Agent{}, err
	}
	return theauth.Agent{
		ID: aid, OwnerUserID: ownerID, OrganizationID: orgID, Name: name, Description: desc,
		Status: status, ClientID: clientID, Scope: sc, CreatedAt: fromMicro(created),
		LastActiveAt: fromNullMicro(lastActive),
	}, nil
}

// InsertAgent stores a. A duplicate id or client_id returns theauth.ErrStorageNotFound.
// An empty Status defaults to active and a zero CreatedAt to now.
func (s *Store) InsertAgent(ctx context.Context, a theauth.Agent) (theauth.Agent, error) {
	if (a.OwnerUserID == nil) == (a.OrganizationID == nil) {
		return theauth.Agent{}, errors.New("theauth sqlite: insert agent: exactly one of OwnerUserID and OrganizationID is required")
	}
	if a.Status == "" {
		a.Status = theauth.AgentStatusActive
	}
	a.CreatedAt = orNow(a.CreatedAt).UTC().Truncate(time.Microsecond)
	scope, err := encodeList(a.Scope)
	if err != nil {
		return theauth.Agent{}, err
	}
	_, err = s.db.ExecContext(ctx, s.q(`
INSERT INTO theauth_agents (`+agentCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		idStr(a.ID), idPtrStr(a.OwnerUserID), idPtrStr(a.OrganizationID), a.Name, a.Description,
		a.Status, a.ClientID, scope, toMicro(a.CreatedAt), toNullMicro(a.LastActiveAt))
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return theauth.Agent{}, fmt.Errorf("theauth sqlite: insert agent: duplicate id or client_id: %w", theauth.ErrStorageNotFound)
		}
		return theauth.Agent{}, wrap("insert agent", err)
	}
	return a, nil
}

// AgentByID implements the agent lookup; a missing row is ErrStorageNotFound.
func (s *Store) AgentByID(ctx context.Context, id theauth.ULID) (*theauth.Agent, error) {
	a, err := scanAgentRow(s.db.QueryRowContext(ctx, s.q(`SELECT `+agentCols+` FROM theauth_agents WHERE id = ?`), idStr(id)))
	if err != nil {
		return nil, notFoundOr("agent by id", err)
	}
	return &a, nil
}

// AgentByClientID looks an agent up by its OAuth client id.
func (s *Store) AgentByClientID(ctx context.Context, clientID string) (*theauth.Agent, error) {
	a, err := scanAgentRow(s.db.QueryRowContext(ctx, s.q(`SELECT `+agentCols+` FROM theauth_agents WHERE client_id = ?`), clientID))
	if err != nil {
		return nil, notFoundOr("agent by client id", err)
	}
	return &a, nil
}

// AgentsByOwner lists the agents of a user or organization, oldest first. The
// owner must set UserID or OrganizationID (UserID wins when both are set).
func (s *Store) AgentsByOwner(ctx context.Context, owner theauth.AgentOwner) ([]theauth.Agent, error) {
	var (
		q   string
		arg string
	)
	switch {
	case owner.UserID != nil:
		q, arg = `SELECT `+agentCols+` FROM theauth_agents WHERE owner_user_id = ? ORDER BY created_at ASC, id ASC`, idStr(*owner.UserID)
	case owner.OrganizationID != nil:
		q, arg = `SELECT `+agentCols+` FROM theauth_agents WHERE organization_id = ? ORDER BY created_at ASC, id ASC`, idStr(*owner.OrganizationID)
	default:
		return nil, errors.New("theauth sqlite: AgentsByOwner requires a non-nil owner field")
	}
	rows, err := s.db.QueryContext(ctx, s.q(q), arg)
	if err != nil {
		return nil, wrap("agents by owner", err)
	}
	defer func() { _ = rows.Close() }()
	var out []theauth.Agent
	for rows.Next() {
		a, err := scanAgentRow(rows)
		if err != nil {
			return nil, wrap("scan agent", err)
		}
		out = append(out, a)
	}
	return out, wrap("agents by owner", rows.Err())
}

// UpdateAgentStatus sets the lifecycle status. The service layer owns the state machine;
// a single UPDATE serializes concurrent changes.
func (s *Store) UpdateAgentStatus(ctx context.Context, id theauth.ULID, status string, _ time.Time) error {
	switch status {
	case theauth.AgentStatusActive, theauth.AgentStatusSuspended, theauth.AgentStatusRevoked:
	default:
		return fmt.Errorf("theauth sqlite: update agent status: invalid status %q", status)
	}
	res, err := s.db.ExecContext(ctx, s.q(`UPDATE theauth_agents SET status = ? WHERE id = ?`), status, idStr(id))
	if err != nil {
		return wrap("update agent status", err)
	}
	return requireRows("update agent status", res)
}

// UpdateAgentLastActive records the last activity time.
func (s *Store) UpdateAgentLastActive(ctx context.Context, id theauth.ULID, at time.Time) error {
	res, err := s.db.ExecContext(ctx, s.q(`UPDATE theauth_agents SET last_active_at = ? WHERE id = ?`), toMicro(at), idStr(id))
	if err != nil {
		return wrap("update agent last active", err)
	}
	return requireRows("update agent last active", res)
}

// InsertAgentCredential stores a credential row. A duplicate id returns
// ErrStorageNotFound.
func (s *Store) InsertAgentCredential(ctx context.Context, c theauth.AgentCredential) error {
	created := orNow(c.CreatedAt)
	val := c.ValueEnc
	if val == nil {
		val = []byte{}
	}
	_, err := s.db.ExecContext(ctx, s.q(`
INSERT INTO theauth_agent_credentials (`+agentCredCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`),
		idStr(c.ID), idStr(c.AgentID), c.Kind, val, toMicro(created),
		toNullMicro(c.ExpiresAt), toNullMicro(c.LastUsedAt), toNullMicro(c.RevokedAt))
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return fmt.Errorf("theauth sqlite: insert agent credential: duplicate id: %w", theauth.ErrStorageNotFound)
		}
		return wrap("insert agent credential", err)
	}
	return nil
}

// AgentCredentialsByAgentID returns every credential of the agent, oldest
// first, including revoked rows.
func (s *Store) AgentCredentialsByAgentID(ctx context.Context, agentID theauth.ULID) ([]theauth.AgentCredential, error) {
	rows, err := s.db.QueryContext(ctx, s.q(`SELECT `+agentCredCols+` FROM theauth_agent_credentials WHERE agent_id = ? ORDER BY created_at ASC, id ASC`), idStr(agentID))
	if err != nil {
		return nil, wrap("agent credentials", err)
	}
	defer func() { _ = rows.Close() }()
	var out []theauth.AgentCredential
	for rows.Next() {
		var (
			id, agent, kind              string
			val                          []byte
			created                      int64
			expires, lastUsed, revokedAt sql.NullInt64
		)
		if err := rows.Scan(&id, &agent, &kind, &val, &created, &expires, &lastUsed, &revokedAt); err != nil {
			return nil, wrap("scan agent credential", err)
		}
		cid, err := parseID(id)
		if err != nil {
			return nil, err
		}
		aid, err := parseID(agent)
		if err != nil {
			return nil, err
		}
		out = append(out, theauth.AgentCredential{
			ID: cid, AgentID: aid, Kind: kind, ValueEnc: val, CreatedAt: fromMicro(created),
			ExpiresAt: fromNullMicro(expires), LastUsedAt: fromNullMicro(lastUsed), RevokedAt: fromNullMicro(revokedAt),
		})
	}
	return out, wrap("agent credentials", rows.Err())
}

// RevokeAgentCredential sets revoked_at once. A repeat revoke returns ErrStorageNotFound,
// as the other adapters do.
func (s *Store) RevokeAgentCredential(ctx context.Context, id theauth.ULID, at time.Time) error {
	res, err := s.db.ExecContext(ctx, s.q(`UPDATE theauth_agent_credentials SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`), toMicro(at), idStr(id))
	if err != nil {
		return wrap("revoke agent credential", err)
	}
	return requireRows("revoke agent credential", res)
}

// UpdateAgentCredentialLastUsed records credential use. Like Postgres it does
// not fail on a missing row.
func (s *Store) UpdateAgentCredentialLastUsed(ctx context.Context, id theauth.ULID, at time.Time) error {
	_, err := s.db.ExecContext(ctx, s.q(`UPDATE theauth_agent_credentials SET last_used_at = ? WHERE id = ?`), toMicro(at), idStr(id))
	return wrap("update agent credential last used", err)
}
