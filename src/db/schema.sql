-- Agent registry: each agent claims a unique name and provides a webhook URL
CREATE TABLE IF NOT EXISTS agents (
    id TEXT PRIMARY KEY,           -- unique agent ID (UUID)
    name TEXT UNIQUE NOT NULL,     -- human-readable name (e.g. "alice")
    api_key TEXT UNIQUE NOT NULL,  -- secret key for authentication
    webhook_url TEXT,              -- where to push messages (optional)
    visibility TEXT DEFAULT 'private',  -- 'public' or 'private' (who can message me)
    public_key_pem TEXT,           -- RSA public key for E2EE
    manifest TEXT,                 -- JSON: { description, capabilities, tags, version }
    created_at TIMESTAMP DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- Contacts allowlist: agents can only receive messages from their contacts (unless public)
CREATE TABLE IF NOT EXISTS contacts (
    agent_id TEXT NOT NULL,        -- the agent who owns this contact list
    contact_agent_id TEXT NOT NULL, -- the agent they've added as a contact
    created_at TIMESTAMP DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (agent_id, contact_agent_id),
    FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE CASCADE,
    FOREIGN KEY (contact_agent_id) REFERENCES agents(id) ON DELETE CASCADE
);

-- Message queue: all messages pass through here
CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY,                          -- unique message ID
    from_agent_id TEXT NOT NULL,                  -- sender
    to_agent_id TEXT NOT NULL,                    -- recipient
    type TEXT DEFAULT 'message',                 -- message, reply, system
    payload TEXT NOT NULL,                        -- JSON payload
    reply_to TEXT,                                -- URL for direct replies
    status TEXT DEFAULT 'queued',                -- queued, delivered, failed
    attempts INTEGER DEFAULT 0,                   -- delivery attempt count
    created_at TIMESTAMP DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    delivered_at TIMESTAMP,
    FOREIGN KEY (from_agent_id) REFERENCES agents(id),
    FOREIGN KEY (to_agent_id) REFERENCES agents(id)
);

-- Index for efficient inbox queries
CREATE INDEX IF NOT EXISTS idx_messages_recipient ON messages(to_agent_id, status);
CREATE INDEX IF NOT EXISTS idx_messages_status ON messages(status, attempts);
