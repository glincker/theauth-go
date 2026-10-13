ALTER TABLE oauth_refresh_tokens
    DROP COLUMN IF EXISTS amr,
    DROP COLUMN IF EXISTS acr,
    DROP COLUMN IF EXISTS auth_time;
ALTER TABLE oauth_authorization_codes
    DROP COLUMN IF EXISTS amr,
    DROP COLUMN IF EXISTS acr,
    DROP COLUMN IF EXISTS auth_time;
