CREATE TABLE IF NOT EXISTS devices (
    id UUID PRIMARY KEY,
    device_key_hash TEXT NOT NULL UNIQUE,
    secret_hash TEXT NOT NULL,
    device_meta JSONB NOT NULL DEFAULT '{}'::jsonb,
    token_hash TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS presence (
    device_id UUID PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    online BOOLEAN NOT NULL DEFAULT false,
    last_seen TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS otp (
    id UUID PRIMARY KEY,
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    otp_hash TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    attempts_remaining INTEGER NOT NULL DEFAULT 5,
    used BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sessions (
    id UUID PRIMARY KEY,
    agent_device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    viewer_device_id UUID,
    status TEXT NOT NULL CHECK (status IN ('REQUESTED', 'NOTIFIED', 'ACCEPTED', 'CONNECTING', 'CONNECTED', 'RECONNECTING', 'FAILED', 'ENDED')),
    transport_mode TEXT,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS session_events (
    id BIGSERIAL PRIMARY KEY,
    session_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    from_state TEXT,
    to_state TEXT,
    reason TEXT,
    payload JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_presence_device_id ON presence(device_id);
CREATE INDEX IF NOT EXISTS idx_otp_device_id ON otp(device_id);
CREATE INDEX IF NOT EXISTS idx_otp_expires_at ON otp(expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_agent_device_id ON sessions(agent_device_id);
CREATE INDEX IF NOT EXISTS idx_sessions_status ON sessions(status);
CREATE INDEX IF NOT EXISTS idx_session_events_session_id ON session_events(session_id);
CREATE INDEX IF NOT EXISTS idx_session_events_created_at ON session_events(created_at);
