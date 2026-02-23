CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,
    email TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_lower_unique ON users ((lower(email)));

ALTER TABLE devices ADD COLUMN IF NOT EXISTS owner_user_id UUID REFERENCES users(id) ON DELETE SET NULL;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS public_id TEXT;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS device_name TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_public_id_unique ON devices (public_id) WHERE public_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_devices_owner_user_id ON devices (owner_user_id);

CREATE TABLE IF NOT EXISTS user_access_tokens (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_user_access_tokens_user_id ON user_access_tokens (user_id);
CREATE INDEX IF NOT EXISTS idx_user_access_tokens_expires_at ON user_access_tokens (expires_at);

CREATE TABLE IF NOT EXISTS user_refresh_tokens (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_user_refresh_tokens_user_id ON user_refresh_tokens (user_id);
CREATE INDEX IF NOT EXISTS idx_user_refresh_tokens_expires_at ON user_refresh_tokens (expires_at);

CREATE TABLE IF NOT EXISTS bootstrap_tokens (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    platform TEXT,
    device_name TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    used BOOLEAN NOT NULL DEFAULT false,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_bootstrap_tokens_user_id ON bootstrap_tokens (user_id);
CREATE INDEX IF NOT EXISTS idx_bootstrap_tokens_expires_at ON bootstrap_tokens (expires_at);
