-- Add visibility column to agents table (defaults to 'private')
ALTER TABLE agents ADD COLUMN visibility TEXT DEFAULT 'private';

-- Create contacts allowlist table
CREATE TABLE IF NOT EXISTS contacts (
    agent_id TEXT NOT NULL,
    contact_agent_id TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (agent_id, contact_agent_id),
    FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE CASCADE,
    FOREIGN KEY (contact_agent_id) REFERENCES agents(id) ON DELETE CASCADE
);
