-- Shared tables: tokens and tunnel_log.
-- Timestamps stored as TIMESTAMPTZ; sqlx chrono maps DateTime<Utc> directly.

CREATE TABLE IF NOT EXISTS tokens (
    id           TEXT PRIMARY KEY,
    token_hash   TEXT NOT NULL UNIQUE,
    label        TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL,
    last_used_at TIMESTAMPTZ,
    scope        TEXT
);

CREATE TABLE IF NOT EXISTS tunnel_log (
    id               TEXT PRIMARY KEY,
    tunnel_id        TEXT NOT NULL,
    protocol         TEXT NOT NULL,
    label            TEXT NOT NULL,
    session_id       TEXT NOT NULL,
    token_id         TEXT REFERENCES tokens(id) ON DELETE SET NULL,
    registered_at    TIMESTAMPTZ NOT NULL,
    unregistered_at  TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_tunnel_log_tunnel_id ON tunnel_log (tunnel_id);
CREATE INDEX IF NOT EXISTS idx_tunnel_log_registered ON tunnel_log (registered_at DESC);
