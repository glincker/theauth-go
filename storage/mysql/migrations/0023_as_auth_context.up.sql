-- 0023: authentication context (OIDC auth_time, acr, amr) recorded on the
-- authorization code and carried unchanged through the refresh token family.
-- amr is a space separated list; NULL auth_time means the grant carried none.
ALTER TABLE oauth_authorization_codes
    ADD COLUMN auth_time DATETIME(6) NULL,
    ADD COLUMN acr       VARCHAR(255) NOT NULL DEFAULT '',
    ADD COLUMN amr       VARCHAR(255) NOT NULL DEFAULT '';

ALTER TABLE oauth_refresh_tokens
    ADD COLUMN auth_time DATETIME(6) NULL,
    ADD COLUMN acr       VARCHAR(255) NOT NULL DEFAULT '',
    ADD COLUMN amr       VARCHAR(255) NOT NULL DEFAULT '';
