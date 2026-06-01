-- Message TTL: optional time-to-live for time-sensitive messages

ALTER TABLE messages ADD COLUMN expires_at TIMESTAMP;

-- Index for efficient TTL expiry queries and cleanup
CREATE INDEX IF NOT EXISTS idx_messages_expires_at ON messages(expires_at);
