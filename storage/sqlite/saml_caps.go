package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/glincker/theauth-go/v2"
)

// saml_caps.go: SAMLStorage over migration 0014. Only public IdP certificate and URLs are stored.

var _ theauth.SAMLStorage = (*Store)(nil)

const samlConnCols = `id, organization_id, idp_entity_id, idp_sso_url, idp_x509_cert, sp_entity_id, sp_acs_url,
attribute_map, created_at, updated_at`

func scanSAMLConnection(r scanner) (theauth.SAMLConnection, error) {
	var (
		id, org, idpEntity, idpSSO, cert, spEntity, acs, amap string
		created, updated                                      int64
	)
	if err := r.Scan(&id, &org, &idpEntity, &idpSSO, &cert, &spEntity, &acs, &amap, &created, &updated); err != nil {
		return theauth.SAMLConnection{}, err
	}
	cid, err := parseID(id)
	if err != nil {
		return theauth.SAMLConnection{}, err
	}
	oid, err := parseID(org)
	if err != nil {
		return theauth.SAMLConnection{}, err
	}
	var m theauth.SAMLAttributeMap
	if err := json.Unmarshal([]byte(amap), &m); err != nil {
		return theauth.SAMLConnection{}, err
	}
	return theauth.SAMLConnection{
		ID: cid, OrganizationID: oid, IdPEntityID: idpEntity, IdPSSOURL: idpSSO, IdPX509Cert: cert,
		SPEntityID: spEntity, SPACSURL: acs, AttributeMap: m,
		CreatedAt: fromMicro(created), UpdatedAt: fromMicro(updated),
	}, nil
}

// InsertSAMLConnection stores a connection bound to an existing organization.
func (s *Store) InsertSAMLConnection(ctx context.Context, c theauth.SAMLConnection) (theauth.SAMLConnection, error) {
	amap, err := json.Marshal(c.AttributeMap)
	if err != nil {
		return theauth.SAMLConnection{}, wrap("insert saml connection", err)
	}
	created := orNow(c.CreatedAt)
	updated := c.UpdatedAt
	if updated.IsZero() {
		updated = created
	}
	out, err := scanSAMLConnection(s.db.QueryRowContext(ctx, s.q(`
INSERT INTO theauth_saml_connections (`+samlConnCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
RETURNING `+samlConnCols),
		idStr(c.ID), idStr(c.OrganizationID), c.IdPEntityID, c.IdPSSOURL, c.IdPX509Cert,
		c.SPEntityID, c.SPACSURL, string(amap), toMicro(created), toMicro(updated)))
	if err != nil {
		return theauth.SAMLConnection{}, wrap("insert saml connection", err)
	}
	return out, nil
}

// UpdateSAMLConnectionRow rewrites the IdP and SP settings of a connection.
func (s *Store) UpdateSAMLConnectionRow(ctx context.Context, c theauth.SAMLConnection) error {
	amap, err := json.Marshal(c.AttributeMap)
	if err != nil {
		return wrap("update saml connection", err)
	}
	res, err := s.db.ExecContext(ctx, s.q(`
UPDATE theauth_saml_connections SET idp_entity_id = ?, idp_sso_url = ?, idp_x509_cert = ?,
    sp_entity_id = ?, sp_acs_url = ?, attribute_map = ?, updated_at = ?
WHERE id = ?`),
		c.IdPEntityID, c.IdPSSOURL, c.IdPX509Cert, c.SPEntityID, c.SPACSURL, string(amap),
		toMicro(time.Now()), idStr(c.ID))
	if err != nil {
		return wrap("update saml connection", err)
	}
	return requireRows("update saml connection", res)
}

// DeleteSAMLConnection removes a connection and, by cascade, its identities.
func (s *Store) DeleteSAMLConnection(ctx context.Context, id theauth.ULID) error {
	res, err := s.db.ExecContext(ctx, s.q(`DELETE FROM theauth_saml_connections WHERE id = ?`), idStr(id))
	if err != nil {
		return wrap("delete saml connection", err)
	}
	return requireRows("delete saml connection", res)
}

// SAMLConnectionByID returns the connection with the given ID.
func (s *Store) SAMLConnectionByID(ctx context.Context, id theauth.ULID) (*theauth.SAMLConnection, error) {
	c, err := scanSAMLConnection(s.db.QueryRowContext(ctx,
		s.q(`SELECT `+samlConnCols+` FROM theauth_saml_connections WHERE id = ?`), idStr(id)))
	if err != nil {
		return nil, notFoundOr("saml connection by id", err)
	}
	return &c, nil
}

// SAMLConnectionsByOrg lists an organization's connections, oldest first.
func (s *Store) SAMLConnectionsByOrg(ctx context.Context, orgID theauth.ULID) ([]theauth.SAMLConnection, error) {
	rows, err := s.db.QueryContext(ctx, s.q(`SELECT `+samlConnCols+
		` FROM theauth_saml_connections WHERE organization_id = ? ORDER BY created_at ASC, id ASC`), idStr(orgID))
	if err != nil {
		return nil, wrap("saml connections by org", err)
	}
	defer func() { _ = rows.Close() }()
	out := []theauth.SAMLConnection{}
	for rows.Next() {
		c, err := scanSAMLConnection(rows)
		if err != nil {
			return nil, wrap("saml connections by org", err)
		}
		out = append(out, c)
	}
	return out, wrap("saml connections by org", rows.Err())
}

const samlIdentityCols = `id, connection_id, user_id, name_id, name_id_format, last_login_at, created_at`

func scanSAMLIdentity(r scanner) (theauth.SAMLIdentity, error) {
	var (
		id, conn, user, nameID, format string
		lastLogin                      sql.NullInt64
		created                        int64
	)
	if err := r.Scan(&id, &conn, &user, &nameID, &format, &lastLogin, &created); err != nil {
		return theauth.SAMLIdentity{}, err
	}
	iid, err := parseID(id)
	if err != nil {
		return theauth.SAMLIdentity{}, err
	}
	cid, err := parseID(conn)
	if err != nil {
		return theauth.SAMLIdentity{}, err
	}
	uid, err := parseID(user)
	if err != nil {
		return theauth.SAMLIdentity{}, err
	}
	return theauth.SAMLIdentity{
		ID: iid, ConnectionID: cid, UserID: uid, NameID: nameID, NameIDFormat: format,
		LastLoginAt: fromNullMicro(lastLogin), CreatedAt: fromMicro(created),
	}, nil
}

// UpsertSAMLIdentity inserts the (connection, NameID) identity or rebinds an existing one.
func (s *Store) UpsertSAMLIdentity(ctx context.Context, i theauth.SAMLIdentity) (theauth.SAMLIdentity, error) {
	out, err := scanSAMLIdentity(s.db.QueryRowContext(ctx, s.q(`
INSERT INTO theauth_saml_identities (id, connection_id, user_id, name_id, name_id_format, created_at)
VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT (connection_id, name_id) DO UPDATE SET user_id = excluded.user_id, name_id_format = excluded.name_id_format
RETURNING `+samlIdentityCols),
		idStr(i.ID), idStr(i.ConnectionID), idStr(i.UserID), i.NameID, i.NameIDFormat, toMicro(orNow(i.CreatedAt))))
	if err != nil {
		return theauth.SAMLIdentity{}, wrap("upsert saml identity", err)
	}
	return out, nil
}

// SAMLIdentityByConnectionAndNameID returns the identity for a NameID on a connection.
func (s *Store) SAMLIdentityByConnectionAndNameID(ctx context.Context, connectionID theauth.ULID, nameID string) (*theauth.SAMLIdentity, error) {
	i, err := scanSAMLIdentity(s.db.QueryRowContext(ctx, s.q(`SELECT `+samlIdentityCols+
		` FROM theauth_saml_identities WHERE connection_id = ? AND name_id = ?`), idStr(connectionID), nameID))
	if err != nil {
		return nil, notFoundOr("saml identity", err)
	}
	return &i, nil
}

// TouchSAMLIdentityLastLogin records a login time on an identity.
func (s *Store) TouchSAMLIdentityLastLogin(ctx context.Context, id theauth.ULID, at time.Time) error {
	_, err := s.db.ExecContext(ctx, s.q(`UPDATE theauth_saml_identities SET last_login_at = ? WHERE id = ?`),
		toMicro(at), idStr(id))
	return wrap("touch saml identity", err)
}
