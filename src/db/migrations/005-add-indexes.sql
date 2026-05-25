-- Performance indexes for scaling to thousands of agents

-- Agent lookups: every authenticated request scans by api_key; directory scans by name
CREATE INDEX IF NOT EXISTS idx_agents_api_key ON agents(api_key);
CREATE INDEX IF NOT EXISTS idx_agents_name ON agents(name);
CREATE INDEX IF NOT EXISTS idx_agents_visibility ON agents(visibility);

-- Contacts lookups: permission checks join on both columns
CREATE INDEX IF NOT EXISTS idx_contacts_agent ON contacts(agent_id);
CREATE INDEX IF NOT EXISTS idx_contacts_contact_agent ON contacts(contact_agent_id);

-- Messages: delivery queries and cleanup scans
CREATE INDEX IF NOT EXISTS idx_messages_created_at ON messages(created_at);
CREATE INDEX IF NOT EXISTS idx_messages_delivered_at ON messages(delivered_at);
CREATE INDEX IF NOT EXISTS idx_messages_from_agent ON messages(from_agent_id);

-- Handshakes: per-agent daily limit queries
CREATE INDEX IF NOT EXISTS idx_handshakes_from_agent ON handshakes(from_agent_id);
CREATE INDEX IF NOT EXISTS idx_handshakes_created_at ON handshakes(created_at);
