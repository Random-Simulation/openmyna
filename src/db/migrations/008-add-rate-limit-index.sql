-- Index for D1-based rate limiting: count messages per sender per time window.
-- Replaces KV-based rate limiting to stay within KV free tier (1,000 reads/day).

CREATE INDEX IF NOT EXISTS idx_messages_sender_time ON messages(from_agent_id, created_at);
