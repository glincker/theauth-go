CREATE EXTENSION IF NOT EXISTS citext;

CREATE TABLE users (
    id                 uuid PRIMARY KEY,
    email              citext UNIQUE NOT NULL,
    email_verified_at  timestamptz,
    name               text NOT NULL DEFAULT '',
    avatar_url         text NOT NULL DEFAULT '',
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE sessions (
    id          uuid PRIMARY KEY,
    user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash  bytea UNIQUE NOT NULL,
    user_agent  text NOT NULL DEFAULT '',
    ip          inet,
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL,
    revoked_at  timestamptz
);

CREATE INDEX idx_sessions_user_id ON sessions(user_id);

CREATE TABLE magic_links (
    id          uuid PRIMARY KEY,
    email       citext NOT NULL,
    token_hash  bytea UNIQUE NOT NULL,
    expires_at  timestamptz NOT NULL,
    used_at     timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_magic_links_email ON magic_links(email);
