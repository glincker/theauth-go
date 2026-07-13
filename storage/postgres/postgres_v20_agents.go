package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/storage"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// postgres_v20_agents.go: Postgres adapter for the v2.0 phase 3 + 4 tables
// (agents, agent_credentials, delegation_grants). Hand-rolled pgx queries
// matching the alpha.1 precedent in postgres_v20.go. sqlc regeneration for
// these tables is deferred; the existing sqlc directory stays untouched.

// ---------- agents ----------

func (s *Store) InsertAgent(ctx context.Context, a theauth.Agent) (theauth.Agent, error) {
	const q = `
INSERT INTO agents (id, owner_user_id, organization_id, name, description, status, client_id, scope_grant, created_at, last_active_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
RETURNING id, created_at`
	created := a.CreatedAt
	if created.IsZero() {
		created = time.Now()
	}
	status := a.Status
	if status == "" {
		status = theauth.AgentStatusActive
	}
	row := s.pool.QueryRow(ctx, q,
		ulidToPgUUID(a.ID),
		ulidPtrToPgUUID(a.OwnerUserID),
		ulidPtrToPgUUID(a.OrganizationID),
		a.Name,
		a.Description,
		status,
		a.ClientID,
		a.Scope,
		timeToTs(created),
		timePtrToTs(a.LastActiveAt),
	)
	var id pgtype.UUID
	var createdAt pgtype.Timestamptz
	if err := row.Scan(&id, &createdAt); err != nil {
		return theauth.Agent{}, err
	}
	a.ID = pgUUIDToULID(id)
	a.CreatedAt = tsToTime(createdAt)
	a.Status = status
	return a, nil
}

func (s *Store) AgentByID(ctx context.Context, id theauth.ULID) (*theauth.Agent, error) {
	const q = `
SELECT id, owner_user_id, organization_id, name, description, status, client_id, scope_grant, created_at, last_active_at
FROM agents WHERE id = $1`
	a, err := scanAgent(s.pool.QueryRow(ctx, q, ulidToPgUUID(id)))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, storage.ErrNotFound
		}
		return nil, err
	}
	return &a, nil
}

func (s *Store) AgentByClientID(ctx context.Context, clientID string) (*theauth.Agent, error) {
	const q = `
SELECT id, owner_user_id, organization_id, name, description, status, client_id, scope_grant, created_at, last_active_at
FROM agents WHERE client_id = $1`
	a, err := scanAgent(s.pool.QueryRow(ctx, q, clientID))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, storage.ErrNotFound
		}
		return nil, err
	}
	return &a, nil
}

func (s *Store) AgentsByOwner(ctx context.Context, owner theauth.AgentOwner) ([]theauth.Agent, error) {
	var q string
	var arg any
	switch {
	case owner.UserID != nil:
		q = `SELECT id, owner_user_id, organization_id, name, description, status, client_id, scope_grant, created_at, last_active_at
FROM agents WHERE owner_user_id = $1 ORDER BY created_at ASC`
		arg = ulidToPgUUID(*owner.UserID)
	case owner.OrganizationID != nil:
		q = `SELECT id, owner_user_id, organization_id, name, description, status, client_id, scope_grant, created_at, last_active_at
FROM agents WHERE organization_id = $1 ORDER BY created_at ASC`
		arg = ulidToPgUUID(*owner.OrganizationID)
	default:
		return nil, errors.New("postgres: AgentsByOwner requires a non-nil owner field")
	}
	rows, err := s.pool.Query(ctx, q, arg)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []theauth.Agent
	for rows.Next() {
		a, err := scanAgent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) UpdateAgentStatus(ctx context.Context, id theauth.ULID, status string, _ time.Time) error {
	const q = `UPDATE agents SET status = $2 WHERE id = $1`
	tag, err := s.pool.Exec(ctx, q, ulidToPgUUID(id), status)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func (s *Store) UpdateAgentLastActive(ctx context.Context, id theauth.ULID, at time.Time) error {
	const q = `UPDATE agents SET last_active_at = $2 WHERE id = $1`
	tag, err := s.pool.Exec(ctx, q, ulidToPgUUID(id), timeToTs(at))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return nil
}

// ---------- agent credentials ----------

func (s *Store) InsertAgentCredential(ctx context.Context, c theauth.AgentCredential) error {
	const q = `
INSERT INTO agent_credentials (id, agent_id, kind, value_enc, created_at, expires_at, last_used_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)`
	created := c.CreatedAt
	if created.IsZero() {
		created = time.Now()
	}
	_, err := s.pool.Exec(ctx, q,
		ulidToPgUUID(c.ID),
		ulidToPgUUID(c.AgentID),
		c.Kind,
		c.ValueEnc,
		timeToTs(created),
		timePtrToTs(c.ExpiresAt),
		timePtrToTs(c.LastUsedAt),
	)
	return err
}

func (s *Store) AgentCredentialsByAgentID(ctx context.Context, agentID theauth.ULID) ([]theauth.AgentCredential, error) {
	const q = `
SELECT id, agent_id, kind, value_enc, created_at, expires_at, last_used_at, revoked_at
FROM agent_credentials WHERE agent_id = $1 ORDER BY created_at ASC`
	rows, err := s.pool.Query(ctx, q, ulidToPgUUID(agentID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []theauth.AgentCredential
	for rows.Next() {
		c, err := scanAgentCredential(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) RevokeAgentCredential(ctx context.Context, id theauth.ULID, at time.Time) error {
	const q = `UPDATE agent_credentials SET revoked_at = $2 WHERE id = $1 AND revoked_at IS NULL`
	tag, err := s.pool.Exec(ctx, q, ulidToPgUUID(id), timeToTs(at))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func (s *Store) UpdateAgentCredentialLastUsed(ctx context.Context, id theauth.ULID, at time.Time) error {
	const q = `UPDATE agent_credentials SET last_used_at = $2 WHERE id = $1`
	_, err := s.pool.Exec(ctx, q, ulidToPgUUID(id), timeToTs(at))
	return err
}

// ---------- delegation grants ----------

func (s *Store) InsertDelegationGrant(ctx context.Context, g theauth.DelegationGrant) (theauth.DelegationGrant, error) {
	const q = `
INSERT INTO delegation_grants (id, user_id, agent_id, organization_id, scope_grant, resource, max_duration_seconds, created_at, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
RETURNING id, created_at`
	created := g.CreatedAt
	if created.IsZero() {
		created = time.Now()
	}
	row := s.pool.QueryRow(ctx, q,
		ulidToPgUUID(g.ID),
		ulidToPgUUID(g.UserID),
		ulidToPgUUID(g.AgentID),
		ulidPtrToPgUUID(g.OrganizationID),
		g.Scope,
		g.Resource,
		g.MaxDurationSeconds,
		timeToTs(created),
		timePtrToTs(g.ExpiresAt),
	)
	var id pgtype.UUID
	var createdAt pgtype.Timestamptz
	if err := row.Scan(&id, &createdAt); err != nil {
		if isUniqueViolation(err, "") {
			return theauth.DelegationGrant{}, storage.ErrNotFound
		}
		return theauth.DelegationGrant{}, err
	}
	g.ID = pgUUIDToULID(id)
	g.CreatedAt = tsToTime(createdAt)
	return g, nil
}

func (s *Store) DelegationGrantByID(ctx context.Context, id theauth.ULID) (*theauth.DelegationGrant, error) {
	const q = `
SELECT id, user_id, agent_id, organization_id, scope_grant, resource, max_duration_seconds, created_at, expires_at, revoked_at, revocation_note
FROM delegation_grants WHERE id = $1`
	g, err := scanDelegationGrant(s.pool.QueryRow(ctx, q, ulidToPgUUID(id)))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, storage.ErrNotFound
		}
		return nil, err
	}
	return &g, nil
}

func (s *Store) DelegationGrantByUserAgentResource(ctx context.Context, userID, agentID theauth.ULID, resource string) (*theauth.DelegationGrant, error) {
	const q = `
SELECT id, user_id, agent_id, organization_id, scope_grant, resource, max_duration_seconds, created_at, expires_at, revoked_at, revocation_note
FROM delegation_grants WHERE user_id = $1 AND agent_id = $2 AND resource = $3`
	g, err := scanDelegationGrant(s.pool.QueryRow(ctx, q, ulidToPgUUID(userID), ulidToPgUUID(agentID), resource))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, storage.ErrNotFound
		}
		return nil, err
	}
	return &g, nil
}

func (s *Store) DelegationGrantsByUserID(ctx context.Context, userID theauth.ULID) ([]theauth.DelegationGrant, error) {
	return s.queryDelegationGrants(ctx, `
SELECT id, user_id, agent_id, organization_id, scope_grant, resource, max_duration_seconds, created_at, expires_at, revoked_at, revocation_note
FROM delegation_grants WHERE user_id = $1 ORDER BY created_at ASC`, ulidToPgUUID(userID))
}

func (s *Store) DelegationGrantsByAgentID(ctx context.Context, agentID theauth.ULID) ([]theauth.DelegationGrant, error) {
	return s.queryDelegationGrants(ctx, `
SELECT id, user_id, agent_id, organization_id, scope_grant, resource, max_duration_seconds, created_at, expires_at, revoked_at, revocation_note
FROM delegation_grants WHERE agent_id = $1 ORDER BY created_at ASC`, ulidToPgUUID(agentID))
}

func (s *Store) RevokeDelegationGrant(ctx context.Context, id theauth.ULID, at time.Time, reason string) error {
	const q = `UPDATE delegation_grants SET revoked_at = $2, revocation_note = $3 WHERE id = $1 AND revoked_at IS NULL`
	tag, err := s.pool.Exec(ctx, q, ulidToPgUUID(id), timeToTs(at), reason)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return nil
}

// ---------- internal helpers ----------

func (s *Store) queryDelegationGrants(ctx context.Context, q string, args ...any) ([]theauth.DelegationGrant, error) {
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []theauth.DelegationGrant
	for rows.Next() {
		g, err := scanDelegationGrant(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

func scanAgent(row pgRowScanner) (theauth.Agent, error) {
	var (
		id, ownerUser, orgID         pgtype.UUID
		name, desc, status, clientID string
		scope                        []string
		createdAt, lastActiveAt      pgtype.Timestamptz
	)
	if err := row.Scan(&id, &ownerUser, &orgID, &name, &desc, &status, &clientID, &scope, &createdAt, &lastActiveAt); err != nil {
		return theauth.Agent{}, err
	}
	return theauth.Agent{
		ID:             pgUUIDToULID(id),
		OwnerUserID:    pgUUIDToULIDPtr(ownerUser),
		OrganizationID: pgUUIDToULIDPtr(orgID),
		Name:           name,
		Description:    desc,
		Status:         status,
		ClientID:       clientID,
		Scope:          scope,
		CreatedAt:      tsToTime(createdAt),
		LastActiveAt:   tsToTimePtr(lastActiveAt),
	}, nil
}

func scanAgentCredential(row pgRowScanner) (theauth.AgentCredential, error) {
	var (
		id, agentID                                 pgtype.UUID
		kind                                        string
		valueEnc                                    []byte
		createdAt, expiresAt, lastUsedAt, revokedAt pgtype.Timestamptz
	)
	if err := row.Scan(&id, &agentID, &kind, &valueEnc, &createdAt, &expiresAt, &lastUsedAt, &revokedAt); err != nil {
		return theauth.AgentCredential{}, err
	}
	return theauth.AgentCredential{
		ID:         pgUUIDToULID(id),
		AgentID:    pgUUIDToULID(agentID),
		Kind:       kind,
		ValueEnc:   valueEnc,
		CreatedAt:  tsToTime(createdAt),
		ExpiresAt:  tsToTimePtr(expiresAt),
		LastUsedAt: tsToTimePtr(lastUsedAt),
		RevokedAt:  tsToTimePtr(revokedAt),
	}, nil
}

func scanDelegationGrant(row pgRowScanner) (theauth.DelegationGrant, error) {
	var (
		id, userID, agentID, orgID pgtype.UUID
		scope                      []string
		resource, note             string
		maxDur                     int32
		createdAt, expiresAt       pgtype.Timestamptz
		revokedAt                  pgtype.Timestamptz
	)
	if err := row.Scan(&id, &userID, &agentID, &orgID, &scope, &resource, &maxDur, &createdAt, &expiresAt, &revokedAt, &note); err != nil {
		return theauth.DelegationGrant{}, err
	}
	return theauth.DelegationGrant{
		ID:                 pgUUIDToULID(id),
		UserID:             pgUUIDToULID(userID),
		AgentID:            pgUUIDToULID(agentID),
		OrganizationID:     pgUUIDToULIDPtr(orgID),
		Scope:              scope,
		Resource:           resource,
		MaxDurationSeconds: int(maxDur),
		CreatedAt:          tsToTime(createdAt),
		ExpiresAt:          tsToTimePtr(expiresAt),
		RevokedAt:          tsToTimePtr(revokedAt),
		RevocationNote:     note,
	}, nil
}
