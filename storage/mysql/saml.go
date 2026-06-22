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

// ---------- SAML connections ----------

func (s *Store) InsertSAMLConnection(ctx context.Context, c theauth.SAMLConnection) (theauth.SAMLConnection, error) {
	attrMap, err := json.Marshal(c.AttributeMap)
	if err != nil {
		return theauth.SAMLConnection{}, err
	}
	if attrMap == nil || string(attrMap) == "null" {
		attrMap = []byte("{}")
	}
	_, err = s.db.ExecContext(ctx, `
INSERT INTO saml_connections
    (id, organization_id, idp_entity_id, idp_sso_url, idp_x509_cert,
     sp_entity_id, sp_acs_url, attribute_map, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ulidToBytes(c.ID),
		ulidToBytes(c.OrganizationID),
		c.IdPEntityID,
		c.IdPSSOURL,
		c.IdPX509Cert,
		c.SPEntityID,
		c.SPACSURL,
		attrMap,
		timeUTC(c.CreatedAt),
		timeUTC(c.UpdatedAt),
	)
	if err != nil {
		return theauth.SAMLConnection{}, err
	}
	got, err := s.SAMLConnectionByID(ctx, c.ID)
	if err != nil {
		return theauth.SAMLConnection{}, err
	}
	return *got, nil
}

func (s *Store) UpdateSAMLConnectionRow(ctx context.Context, c theauth.SAMLConnection) error {
	attrMap, err := json.Marshal(c.AttributeMap)
	if err != nil {
		return err
	}
	if string(attrMap) == "null" {
		attrMap = []byte("{}")
	}
	_, err = s.db.ExecContext(ctx, `
UPDATE saml_connections SET
    idp_entity_id = ?, idp_sso_url = ?, idp_x509_cert = ?,
    sp_entity_id = ?, sp_acs_url = ?,
    attribute_map = ?, updated_at = ?
WHERE id = ?`,
		c.IdPEntityID, c.IdPSSOURL, c.IdPX509Cert,
		c.SPEntityID, c.SPACSURL,
		attrMap, timeUTC(time.Now()),
		ulidToBytes(c.ID),
	)
	return err
}

func (s *Store) DeleteSAMLConnection(ctx context.Context, id theauth.ULID) error {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM saml_connections WHERE id = ?`, ulidToBytes(id))
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func (s *Store) SAMLConnectionByID(ctx context.Context, id theauth.ULID) (*theauth.SAMLConnection, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT id, organization_id, idp_entity_id, idp_sso_url, idp_x509_cert,
       sp_entity_id, sp_acs_url, attribute_map, created_at, updated_at
FROM saml_connections WHERE id = ?`, ulidToBytes(id))
	c, err := scanSAMLConnection(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, storage.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (s *Store) SAMLConnectionsByOrg(ctx context.Context, orgID theauth.ULID) ([]theauth.SAMLConnection, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, organization_id, idp_entity_id, idp_sso_url, idp_x509_cert,
       sp_entity_id, sp_acs_url, attribute_map, created_at, updated_at
FROM saml_connections WHERE organization_id = ? ORDER BY created_at ASC`, ulidToBytes(orgID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []theauth.SAMLConnection
	for rows.Next() {
		c, err := scanSAMLConnection(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func scanSAMLConnection(row interface{ Scan(...interface{}) error }) (theauth.SAMLConnection, error) {
	var (
		idB, orgIDB                []byte
		idpEntity, idpSSO, idpCert string
		spEntity, spAcs            string
		attrMapJSON                []byte
		createdAt, updatedAt       time.Time
	)
	if err := row.Scan(
		&idB, &orgIDB, &idpEntity, &idpSSO, &idpCert,
		&spEntity, &spAcs, &attrMapJSON, &createdAt, &updatedAt,
	); err != nil {
		return theauth.SAMLConnection{}, err
	}
	var attrMap theauth.SAMLAttributeMap
	if len(attrMapJSON) > 0 {
		_ = json.Unmarshal(attrMapJSON, &attrMap)
	}
	return theauth.SAMLConnection{
		ID:             bytesToULID(idB),
		OrganizationID: bytesToULID(orgIDB),
		IdPEntityID:    idpEntity,
		IdPSSOURL:      idpSSO,
		IdPX509Cert:    idpCert,
		SPEntityID:     spEntity,
		SPACSURL:       spAcs,
		AttributeMap:   attrMap,
		CreatedAt:      createdAt.UTC(),
		UpdatedAt:      updatedAt.UTC(),
	}, nil
}

// ---------- SAML identities ----------

func (s *Store) UpsertSAMLIdentity(ctx context.Context, i theauth.SAMLIdentity) (theauth.SAMLIdentity, error) {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO saml_identities
    (id, connection_id, user_id, name_id, name_id_format, last_login_at, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?)
ON DUPLICATE KEY UPDATE
    user_id       = VALUES(user_id),
    name_id_format = VALUES(name_id_format),
    last_login_at  = VALUES(last_login_at)`,
		ulidToBytes(i.ID),
		ulidToBytes(i.ConnectionID),
		ulidToBytes(i.UserID),
		i.NameID,
		i.NameIDFormat,
		timePtrToNull(i.LastLoginAt),
		timeUTC(i.CreatedAt),
	)
	if err != nil {
		return theauth.SAMLIdentity{}, err
	}
	got, err := s.SAMLIdentityByConnectionAndNameID(ctx, i.ConnectionID, i.NameID)
	if err != nil {
		return theauth.SAMLIdentity{}, err
	}
	return *got, nil
}

func (s *Store) SAMLIdentityByConnectionAndNameID(ctx context.Context, connectionID theauth.ULID, nameID string) (*theauth.SAMLIdentity, error) {
	var (
		idB, connIDB, userIDB []byte
		nid, nidFormat        string
		lastLoginAt           sql.NullTime
		createdAt             time.Time
	)
	err := s.db.QueryRowContext(ctx, `
SELECT id, connection_id, user_id, name_id, name_id_format, last_login_at, created_at
FROM saml_identities WHERE connection_id = ? AND name_id = ?`,
		ulidToBytes(connectionID), nameID,
	).Scan(&idB, &connIDB, &userIDB, &nid, &nidFormat, &lastLoginAt, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, storage.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	si := theauth.SAMLIdentity{
		ID:           bytesToULID(idB),
		ConnectionID: bytesToULID(connIDB),
		UserID:       bytesToULID(userIDB),
		NameID:       nid,
		NameIDFormat: nidFormat,
		LastLoginAt:  nullTimeToPtr(lastLoginAt),
		CreatedAt:    createdAt.UTC(),
	}
	return &si, nil
}

func (s *Store) TouchSAMLIdentityLastLogin(ctx context.Context, id theauth.ULID, at time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE saml_identities SET last_login_at = ? WHERE id = ?`,
		timeUTC(at), ulidToBytes(id),
	)
	return err
}
