-- SSE event queue: moved from KV to D1 to stay within KV free tier limits.
-- KV free tier: 1,000 reads/day. D1 free tier: 50,000 reads/day.
-- Events are cleaned up by the daily cron (older than 5 minutes).

CREATE TABLE IF NOT EXISTS sse_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT NOT NULL,
    message_id TEXT NOT NULL,
    event TEXT DEFAULT 'message',  -- 'message' or 'handshake'
    created_at TIMESTAMP DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- Index for efficient SSE stream queries (agent + cursor)
CREATE INDEX IF NOT EXISTS idx_sse_events_agent_cursor ON sse_events(agent_id, id);

-- Index for cleanup (find old events to purge)
CREATE INDEX IF NOT EXISTS idx_sse_events_created_at ON sse_events(created_at);
