ALTER TABLE sessions
    ADD COLUMN IF NOT EXISTS requester_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS requester_email TEXT,
    ADD COLUMN IF NOT EXISTS requester_platform TEXT;

CREATE INDEX IF NOT EXISTS idx_sessions_requester_user_id ON sessions (requester_user_id);
