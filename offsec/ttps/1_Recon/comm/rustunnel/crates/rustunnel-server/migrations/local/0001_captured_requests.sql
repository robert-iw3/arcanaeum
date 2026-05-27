-- Per-region local table: captured HTTP request/response pairs.
-- captured_at stored as TEXT (RFC-3339) to avoid SQLite datetime quirks.

CREATE TABLE IF NOT EXISTS captured_requests (
    id             TEXT PRIMARY KEY,
    tunnel_id      TEXT NOT NULL,
    conn_id        TEXT NOT NULL,
    method         TEXT NOT NULL,
    path           TEXT NOT NULL,
    status         INTEGER NOT NULL,
    request_bytes  INTEGER NOT NULL DEFAULT 0,
    response_bytes INTEGER NOT NULL DEFAULT 0,
    duration_ms    INTEGER NOT NULL DEFAULT 0,
    captured_at    TEXT NOT NULL,
    request_body   TEXT,
    response_body  TEXT
);

CREATE INDEX IF NOT EXISTS idx_captured_tunnel
    ON captured_requests (tunnel_id, captured_at DESC);
