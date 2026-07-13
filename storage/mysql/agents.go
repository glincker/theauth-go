package mysql

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/storage"
)

// ---------- Agents ----------

func (s *Store) InsertAgent(ctx context.Context, a theauth.Agent) (theauth.Agent, error) {
	created := a.CreatedAt
	if created.IsZero() {
		created = time.Now()
	}
	status := a.Status
	if status == "" {
		status = theauth.AgentStatusActive
	}
	scopeJSON, _ := json.Marshal(nilToEmptySlice(a.Scope))
	_, err := s.db.ExecContext(ctx, `
INSERT INTO agents
    (id, owner_user_id, organization_id, name, description, status,
     client_id, scope_grant, created_at, last_active_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ulidToBytes(a.ID),
		ulidPtrToBytes(a.OwnerUserID),
		ulidPtrToBytes(a.OrganizationID),
		a.Name,
		a.Description,
		status,
		a.ClientID,
		scopeJSON,
		timeUTC(created),
		timePtrToNull(a.LastActiveAt),
	)
	if err != nil {
		return theauth.Agent{}, err
	}
	got, err := s.AgentByID(ctx, a.ID)
	if err != nil {
		return theauth.Agent{}, err
	}
	return *got, nil
}

func (s *Store) AgentByID(ctx context.Context, id theauth.ULID) (*theauth.Agent, error) {
	a, err := scanAgent(s.db.QueryRowContext(ctx, `
SELECT id, owner_user_id, organization_id, name, description, status,
       client_id, scope_grant, created_at, last_active_at
FROM agents WHERE id = ?`, ulidToBytes(id)))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, storage.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &a, nil
}

func (s *Store) AgentByClientID(ctx context.Context, clientID string) (*theauth.Agent, error) {
	a, err := scanAgent(s.db.QueryRowContext(ctx, `
SELECT id, owner_user_id, organization_id, name, description, status,
       client_id, scope_grant, created_at, last_active_at
FROM agents WHERE client_id = ?`, clientID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, storage.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &a, nil
}

func (s *Store) AgentsByOwner(ctx context.Context, owner theauth.AgentOwner) ([]theauth.Agent, error) {
	var rows *sql.Rows
	var err error
	switch {
	case owner.UserID != nil:
		rows, err = s.db.QueryContext(ctx, `
SELECT id, owner_user_id, organization_id, name, description, status,
       client_id, scope_grant, created_at, last_active_at
FROM agents WHERE owner_user_id = ? ORDER BY created_at ASC`, ulidToBytes(*owner.UserID))
	case owner.OrganizationID != nil:
		rows, err = s.db.QueryContext(ctx, `
SELECT id, owner_user_id, organization_id, name, description, status,
       client_id, scope_grant, created_at, last_active_at
FROM agents WHERE organization_id = ? ORDER BY created_at ASC`, ulidToBytes(*owner.OrganizationID))
	default:
		return nil, errors.New("mysql: AgentsByOwner requires a non-nil owner field")
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
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
	res, err := s.db.ExecContext(ctx,
		`UPDATE agents SET status = ? WHERE id = ?`,
		status, ulidToBytes(id),
	)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func (s *Store) UpdateAgentLastActive(ctx context.Context, id theauth.ULID, at time.Time) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE agents SET last_active_at = ? WHERE id = ?`,
		timeUTC(at), ulidToBytes(id),
	)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func scanAgent(row interface{ Scan(...interface{}) error }) (theauth.Agent, error) {
	var (
		idB, ownerUserB, orgIDB []byte
		name, desc, status      string
		clientID                string
		scopeJSON               []byte
		createdAt               time.Time
		lastActiveAt            sql.NullTime
	)
	if err := row.Scan(
		&idB, &ownerUserB, &orgIDB, &name, &desc, &status,
		&clientID, &scopeJSON, &createdAt, &lastActiveAt,
	); err != nil {
		return theauth.Agent{}, err
	}
	var scope []string
	_ = json.Unmarshal(scopeJSON, &scope)
	return theauth.Agent{
		ID:             bytesToULID(idB),
		OwnerUserID:    bytesToULIDPtr(ownerUserB),
		OrganizationID: bytesToULIDPtr(orgIDB),
		Name:           name,
		Description:    desc,
		Status:         status,
		ClientID:       clientID,
		Scope:          scope,
		CreatedAt:      createdAt.UTC(),
		LastActiveAt:   nullTimeToPtr(lastActiveAt),
	}, nil
}

// ---------- Agent credentials ----------

func (s *Store) InsertAgentCredential(ctx context.Context, c theauth.AgentCredential) error {
	created := c.CreatedAt
	if created.IsZero() {
		created = time.Now()
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO agent_credentials
    (id, agent_id, kind, value_enc, created_at, expires_at, last_used_at)
VALUES (?, ?, ?, ?, ?, ?, ?)`,
		ulidToBytes(c.ID),
		ulidToBytes(c.AgentID),
		c.Kind,
		c.ValueEnc,
		timeUTC(created),
		timePtrToNull(c.ExpiresAt),
		timePtrToNull(c.LastUsedAt),
	)
	return err
}

func (s *Store) AgentCredentialsByAgentID(ctx context.Context, agentID theauth.ULID) ([]theauth.AgentCredential, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, agent_id, kind, value_enc, created_at, expires_at, last_used_at, revoked_at
FROM agent_credentials WHERE agent_id = ? ORDER BY created_at ASC`, ulidToBytes(agentID))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
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
	res, err := s.db.ExecContext(ctx,
		`UPDATE agent_credentials SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`,
		timeUTC(at), ulidToBytes(id),
	)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func (s *Store) UpdateAgentCredentialLastUsed(ctx context.Context, id theauth.ULID, at time.Time) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE agent_credentials SET last_used_at = ? WHERE id = ?`,
		timeUTC(at), ulidToBytes(id),
	)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func scanAgentCredential(row interface{ Scan(...interface{}) error }) (theauth.AgentCredential, error) {
	var (
		idB, agentIDB                    []byte
		kind                             string
		valueEnc                         []byte
		createdAt                        time.Time
		expiresAt, lastUsedAt, revokedAt sql.NullTime
	)
	if err := row.Scan(
		&idB, &agentIDB, &kind, &valueEnc,
		&createdAt, &expiresAt, &lastUsedAt, &revokedAt,
	); err != nil {
		return theauth.AgentCredential{}, err
	}
	return theauth.AgentCredential{
		ID:         bytesToULID(idB),
		AgentID:    bytesToULID(agentIDB),
		Kind:       kind,
		ValueEnc:   valueEnc,
		CreatedAt:  createdAt.UTC(),
		ExpiresAt:  nullTimeToPtr(expiresAt),
		LastUsedAt: nullTimeToPtr(lastUsedAt),
		RevokedAt:  nullTimeToPtr(revokedAt),
	}, nil
}

// ---------- Delegation grants ----------

func (s *Store) InsertDelegationGrant(ctx context.Context, g theauth.DelegationGrant) (theauth.DelegationGrant, error) {
	created := g.CreatedAt
	if created.IsZero() {
		created = time.Now()
	}
	scopeJSON, _ := json.Marshal(nilToEmptySlice(g.Scope))

	// Check uniqueness on (user_id, agent_id, resource) - enforced at app layer
	// since resource is TEXT and cannot be part of a MySQL unique index.
	var existingID []byte
	err := s.db.QueryRowContext(ctx,
		`SELECT id FROM delegation_grants WHERE user_id = ? AND agent_id = ? AND resource = ?`,
		ulidToBytes(g.UserID), ulidToBytes(g.AgentID), g.Resource,
	).Scan(&existingID)
	if err == nil {
		// Conflict: unique constraint violation.
		return theauth.DelegationGrant{}, storage.ErrNotFound
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return theauth.DelegationGrant{}, err
	}

	_, err = s.db.ExecContext(ctx, `
INSERT INTO delegation_grants
    (id, user_id, agent_id, organization_id, scope_grant, resource,
     max_duration_seconds, created_at, expires_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ulidToBytes(g.ID),
		ulidToBytes(g.UserID),
		ulidToBytes(g.AgentID),
		ulidPtrToBytes(g.OrganizationID),
		scopeJSON,
		g.Resource,
		g.MaxDurationSeconds,
		timeUTC(created),
		timePtrToNull(g.ExpiresAt),
	)
	if err != nil {
		return theauth.DelegationGrant{}, err
	}
	got, err := s.DelegationGrantByID(ctx, g.ID)
	if err != nil {
		return theauth.DelegationGrant{}, err
	}
	return *got, nil
}

func (s *Store) DelegationGrantByID(ctx context.Context, id theauth.ULID) (*theauth.DelegationGrant, error) {
	g, err := scanDelegationGrant(s.db.QueryRowContext(ctx, `
SELECT id, user_id, agent_id, organization_id, scope_grant, resource,
       max_duration_seconds, created_at, expires_at, revoked_at, revocation_note
FROM delegation_grants WHERE id = ?`, ulidToBytes(id)))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, storage.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &g, nil
}

func (s *Store) DelegationGrantByUserAgentResource(ctx context.Context, userID, agentID theauth.ULID, resource string) (*theauth.DelegationGrant, error) {
	g, err := scanDelegationGrant(s.db.QueryRowContext(ctx, `
SELECT id, user_id, agent_id, organization_id, scope_grant, resource,
       max_duration_seconds, created_at, expires_at, revoked_at, revocation_note
FROM delegation_grants WHERE user_id = ? AND agent_id = ? AND resource = ?`,
		ulidToBytes(userID), ulidToBytes(agentID), resource))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, storage.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &g, nil
}

func (s *Store) DelegationGrantsByUserID(ctx context.Context, userID theauth.ULID) ([]theauth.DelegationGrant, error) {
	return s.queryDelegationGrants(ctx, `
SELECT id, user_id, agent_id, organization_id, scope_grant, resource,
       max_duration_seconds, created_at, expires_at, revoked_at, revocation_note
FROM delegation_grants WHERE user_id = ? ORDER BY created_at ASC`, ulidToBytes(userID))
}

func (s *Store) DelegationGrantsByAgentID(ctx context.Context, agentID theauth.ULID) ([]theauth.DelegationGrant, error) {
	return s.queryDelegationGrants(ctx, `
SELECT id, user_id, agent_id, organization_id, scope_grant, resource,
       max_duration_seconds, created_at, expires_at, revoked_at, revocation_note
FROM delegation_grants WHERE agent_id = ? ORDER BY created_at ASC`, ulidToBytes(agentID))
}

func (s *Store) RevokeDelegationGrant(ctx context.Context, id theauth.ULID, at time.Time, reason string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE delegation_grants SET revoked_at = ?, revocation_note = ?
		 WHERE id = ? AND revoked_at IS NULL`,
		timeUTC(at), reason, ulidToBytes(id),
	)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func (s *Store) queryDelegationGrants(ctx context.Context, q string, args ...interface{}) ([]theauth.DelegationGrant, error) {
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
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

func scanDelegationGrant(row interface{ Scan(...interface{}) error }) (theauth.DelegationGrant, error) {
	var (
		idB, userIDB, agentIDB, orgIDB []byte
		scopeJSON                      []byte
		resource, note                 string
		maxDur                         int
		createdAt                      time.Time
		expiresAt, revokedAt           sql.NullTime
	)
	if err := row.Scan(
		&idB, &userIDB, &agentIDB, &orgIDB, &scopeJSON, &resource,
		&maxDur, &createdAt, &expiresAt, &revokedAt, &note,
	); err != nil {
		return theauth.DelegationGrant{}, err
	}
	var scope []string
	_ = json.Unmarshal(scopeJSON, &scope)
	return theauth.DelegationGrant{
		ID:                 bytesToULID(idB),
		UserID:             bytesToULID(userIDB),
		AgentID:            bytesToULID(agentIDB),
		OrganizationID:     bytesToULIDPtr(orgIDB),
		Scope:              scope,
		Resource:           resource,
		MaxDurationSeconds: maxDur,
		CreatedAt:          createdAt.UTC(),
		ExpiresAt:          nullTimeToPtr(expiresAt),
		RevokedAt:          nullTimeToPtr(revokedAt),
		RevocationNote:     note,
	}, nil
}
