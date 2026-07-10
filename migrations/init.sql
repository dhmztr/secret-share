-- secret-share database schema

CREATE TYPE user_tier AS ENUM ('free', 'premium', 'enterprise');

CREATE TABLE IF NOT EXISTS users (
    id            BIGSERIAL    PRIMARY KEY,
    email         TEXT         NOT NULL UNIQUE,
    password_hash TEXT         NOT NULL,
    tier          user_tier    NOT NULL DEFAULT 'free',
    quota_left    INTEGER      NOT NULL DEFAULT 5
);

CREATE TABLE IF NOT EXISTS secrets (
    secret_id  UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    v          SMALLINT     NOT NULL,
    nonce      BYTEA        NOT NULL,
    ciphertext BYTEA        NOT NULL,
    max_views  INTEGER      NOT NULL,
    view_count INTEGER      NOT NULL DEFAULT 0,
    expires_at TIMESTAMPTZ  NOT NULL,
    burned_at  TIMESTAMPTZ,
    created_at TIMESTAMPTZ  NOT NULL,
    haslo      TEXT
);

CREATE INDEX IF NOT EXISTS idx_secrets_expires_at ON secrets (expires_at);
CREATE INDEX IF NOT EXISTS idx_users_email        ON users   (email);
