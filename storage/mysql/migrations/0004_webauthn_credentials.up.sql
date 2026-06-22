-- 0004: WebAuthn credentials.
-- transports is stored as JSON array (MySQL has no native text[]).
-- sign_count is BIGINT for monotonic counter; checked strictly-greater at
-- application layer for replay detection.

CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id            BINARY(16) PRIMARY KEY,
    user_id       BINARY(16) NOT NULL,
    credential_id VARBINARY(255) NOT NULL,
    public_key    BLOB NOT NULL,
    sign_count    BIGINT NOT NULL DEFAULT 0,
    transports    JSON NOT NULL,
    aaguid        VARBINARY(16) NOT NULL,
    name          TEXT NOT NULL DEFAULT '',
    created_at    DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    last_used_at  DATETIME(6),
    UNIQUE KEY uq_webauthn_credentials_credential_id (credential_id),
    KEY idx_webauthn_credentials_user_id (user_id),
    CONSTRAINT fk_webauthn_credentials_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
