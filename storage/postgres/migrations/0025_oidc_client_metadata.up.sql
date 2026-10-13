-- 0025: OIDC client metadata (subject_type, post logout redirect URIs and
-- back-channel logout settings) kept as one JSON document per client.
ALTER TABLE oauth_clients ADD COLUMN oidc_metadata text NOT NULL DEFAULT '{}';
