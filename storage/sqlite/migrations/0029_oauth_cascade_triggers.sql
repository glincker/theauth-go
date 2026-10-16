-- 0029: cascade cleanup for the authorization server tables. The OAuth tables
-- carry no foreign keys (codes and tokens may reference ids the contract does
-- not require to exist), so these triggers reproduce the ON DELETE CASCADE the
-- other backends get from their schema: deleting a client removes its codes,
-- refresh tokens and opaque tokens; deleting a user or an organization removes
-- the clients it owns and the codes and refresh tokens issued to it.
CREATE TRIGGER IF NOT EXISTS theauth_oauth_clients_cascade AFTER DELETE ON theauth_oauth_clients
BEGIN
    DELETE FROM theauth_oauth_authorization_codes WHERE client_id = OLD.client_id;
    DELETE FROM theauth_oauth_refresh_tokens WHERE client_id = OLD.client_id;
    DELETE FROM theauth_oauth_opaque_access_tokens WHERE client_id = OLD.client_id;
END;

CREATE TRIGGER IF NOT EXISTS theauth_oauth_users_cascade AFTER DELETE ON theauth_users
BEGIN
    DELETE FROM theauth_oauth_clients WHERE owner_user_id = OLD.id;
    DELETE FROM theauth_oauth_authorization_codes WHERE user_id = OLD.id;
    DELETE FROM theauth_oauth_refresh_tokens WHERE user_id = OLD.id;
END;

CREATE TRIGGER IF NOT EXISTS theauth_oauth_organizations_cascade AFTER DELETE ON theauth_organizations
BEGIN
    DELETE FROM theauth_oauth_clients WHERE owner_organization_id = OLD.id;
    DELETE FROM theauth_oauth_authorization_codes WHERE organization_id = OLD.id;
END;
