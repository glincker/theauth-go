DROP TABLE IF EXISTS oauth_opaque_access_tokens;
ALTER TABLE oauth_refresh_tokens      DROP COLUMN IF EXISTS authorization_details;
ALTER TABLE oauth_authorization_codes DROP COLUMN IF EXISTS authorization_details;
ALTER TABLE oauth_clients
    DROP COLUMN IF EXISTS authorization_details_types,
    DROP COLUMN IF EXISTS access_token_signed_response_alg,
    DROP COLUMN IF EXISTS access_token_format;
