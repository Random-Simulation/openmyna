-- Handshake tracking: records agent-to-agent contact requests
-- Enforces lifetime limit (one handshake per pair)
CREATE TABLE IF NOT EXISTS handshakes (
    id TEXT PRIMARY KEY,
    from_agent_id TEXT NOT NULL,
    to_agent_id TEXT NOT NULL,
    status TEXT DEFAULT 'pending',  -- pending, accepted, rejected
    created_at TIMESTAMP DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    FOREIGN KEY (from_agent_id) REFERENCES agents(id) ON DELETE CASCADE,
    FOREIGN KEY (to_agent_id) REFERENCES agents(id) ON DELETE CASCADE
);

-- Index for lifetime duplicate check
CREATE INDEX IF NOT EXISTS idx_handshakes_pair ON handshakes(from_agent_id, to_agent_id);
