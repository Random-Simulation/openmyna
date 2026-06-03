import { HttpError } from "./errors";

// --- Types ---

interface Agent {
  id: string;
  name: string;
  api_key: string;
  webhook_url: string | null;
  visibility: string;  // 'public' or 'private'
  public_key_pem: string | null;  // RSA public key for E2EE
  manifest: string | null;  // JSON: { description, capabilities, tags, version }
  created_at: string;
}

interface AgentManifest {
  description?: string;
  capabilities?: string[];
  tags?: string[];
  version?: string;
  [key: string]: unknown;
}

interface Message {
  id: string;
  from_agent_id: string;
  to_agent_id: string;
  type: string;
  payload: string;
  reply_to: string | null;
  status: string;
  attempts: number;
  created_at: string;
  delivered_at: string | null;
  expires_at: string | null;  // TTL expiry timestamp
}

interface SendRequest {
  to: string;
  type?: string;
  payload: unknown;
  ttl_seconds?: number;  // optional TTL in seconds (60-86400)
}

interface InboxMessage {
  id: string;
  from: string;
  type: string;
  payload: unknown;
  reply_to: string | null;
  spam: boolean;
  read: boolean;
  created_at: string;
  expires_at?: string | null;  // TTL expiry timestamp
}

// --- Bindings ---

interface Env {
  DB: D1Database;
  RATE_LIMIT: KVNamespace;
}

// --- Constants ---

const MAX_REQUEST_BODY_BYTES = 102400; // 100KB gross request cap
const HANDSHAKE_COOLDOWN_SECONDS = 86400; // 24 hours
const MAX_OUTBOUND_PER_HOUR = 60; // server-side rate limit for messages
const MAX_HANDSHAKES_PER_DAY = 100; // per-agent daily handshake limit
const AGENTS_PAGE_SIZE = 50; // default page size for /agents
const MAX_AGENTS_PAGE_SIZE = 100; // hard cap on /agents page size
const MESSAGE_RETENTION_DAYS = 30; // delete delivered messages after this many days
const FAILED_MESSAGE_RETENTION_DAYS = 7; // delete permanently failed messages sooner
const MIN_TTL_SECONDS = 60; // minimum TTL: 1 minute
const MAX_TTL_SECONDS = 86400; // maximum TTL: 24 hours

// --- Helpers ---

function generateId(): string {
  return crypto.randomUUID();
}

function generateApiKey(): string {
  const bytes = new Uint8Array(24);
  crypto.getRandomValues(bytes);
  return "omy_" + btoa(String.fromCharCode(...bytes)).replace(/=/g, "");
}

function jsonResponse(data: unknown, status: number = 200): Response {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

async function authenticateAgent(
  headers: Headers,
  db: D1Database
): Promise<Agent> {
  const apiKey = headers.get("Authorization")?.replace("Bearer ", "");
  if (!apiKey) throw new HttpError(401, "Missing Authorization header");

  const result = await db
    .prepare("SELECT * FROM agents WHERE api_key = ?")
    .bind(apiKey)
    .first<Agent>();

  if (!result) throw new HttpError(401, "Invalid API key");

  // Default visibility to 'private' for agents registered before this feature
  if (!result.visibility) {
    result.visibility = "private";
  }
  return result;
}

// --- Delivery ---

async function deliverMessage(message: Message, env: Env): Promise<void> {
  const target = await env.DB
    .prepare("SELECT webhook_url FROM agents WHERE id = ?")
    .bind(message.to_agent_id)
    .first<{ webhook_url: string | null }>();

  if (!target?.webhook_url) {
    return;
  }

  const sender = await env.DB
    .prepare("SELECT name FROM agents WHERE id = ?")
    .bind(message.from_agent_id)
    .first<{ name: string }>();

  const deliveryPayload = {
    id: message.id,
    from: sender?.name ?? message.from_agent_id,
    type: message.type,
    payload: JSON.parse(message.payload),
    reply_to: message.reply_to,
    created_at: message.created_at,
  };

  try {
    const resp = await fetch(target.webhook_url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(deliveryPayload),
    });

    if (resp.ok) {
      await env.DB
        .prepare(
          "UPDATE messages SET status = 'delivered', delivered_at = ? WHERE id = ?"
        )
        .bind(new Date().toISOString(), message.id)
        .run();
    } else {
      await incrementAttempts(env.DB, message.id);
    }
  } catch {
    await incrementAttempts(env.DB, message.id);
  }
}

async function incrementAttempts(db: D1Database, messageId: string): Promise<void> {
  await db
    .prepare(
      "UPDATE messages SET attempts = attempts + 1, status = 'failed' WHERE id = ? AND attempts < 5"
    )
    .bind(messageId)
    .run();
}

// --- SSE Event Queue (D1-based) ---
// Fire an SSE event for the recipient agent. Stored in D1 (not KV) to stay within
// KV free tier limits (1,000 reads/day). D1 free tier allows 50,000 reads/day.
// Events are cleaned up by the daily cron (older than 5 minutes).
async function fireSseEvent(
  agentId: string,
  messageId: string,
  eventType: string,
  env: Env
): Promise<void> {
  await env.DB
    .prepare(
      "INSERT INTO sse_events (agent_id, message_id, event) VALUES (?, ?, ?)"
    )
    .bind(agentId, messageId, eventType === "handshake" ? "handshake" : "message")
    .run();
}

// --- SSE Stream Endpoint (D1-based) ---
// Uses D1 instead of KV for event storage. D1 free tier: 50,000 reads/day vs KV: 1,000.
async function handleSseStream(request: Request, env: Env): Promise<Response> {
  const agent = await authenticateAgent(new Headers(request.headers), env.DB);
  const url = new URL(request.url);
  let cursor = parseInt(url.searchParams.get("cursor") ?? "0", 10);

  const stream = new ReadableStream({
    async start(controller) {
      const encoder = new TextEncoder();
      const writeSse = (event: string, data: string, id: number) => {
        let line = `id: ${id}\n`;
        if (event) line += `event: ${event}\n`;
        line += `data: ${data}\n\n`;
        controller.enqueue(encoder.encode(line));
      };
      const writeComment = (comment: string) => {
        controller.enqueue(encoder.encode(`: ${comment}\n\n`));
      };

      try {
        let idle = 0;
        const TIMEOUT = 120; // seconds — reconnect before CF worker timeout (150s)

        while (idle < TIMEOUT) {
          // Check for pending events via D1 (not KV)
          const result = await env.DB
            .prepare(
              "SELECT id, event, message_id FROM sse_events " +
              "WHERE agent_id = ? AND id > ? " +
              "ORDER BY id ASC LIMIT 10"
            )
            .bind(agent.id, cursor)
            .all<Record<string, unknown>>();

          if (result.results.length > 0) {
            for (const evt of result.results) {
              writeSse(
                (evt.event as string) || "message",
                (evt.message_id as string) || "",
                evt.id as number
              );
              cursor = Math.max(cursor, evt.id as number);
            }
            idle = 0;
          } else {
            // Keepalive every 15s (prevents proxy timeouts)
            if (idle > 0 && idle % 15 === 0) {
              writeComment("keepalive");
            }

            // Reconnect signal at 115s
            if (idle >= 115) {
              writeSse("reconnect", "", cursor);
              break;
            }

            idle++;
            // Sleep 1s before next check
            await new Promise(r => setTimeout(r, 1000));
          }
        }
      } catch (err) {
        // Client disconnected or error
      }

      controller.close();
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      "Connection": "keep-alive",
      "X-Accel-Buffering": "no",
    },
  });
}

// --- Routes ---

async function handleRegister(request: Request, env: Env): Promise<Response> {
  const body = (await request.json()) as { name: string; webhook_url?: string; visibility?: string; public_key_pem?: string; manifest?: AgentManifest };

  if (!body?.name || typeof body.name !== "string") {
    throw new HttpError(400, "Missing or invalid 'name' field");
  }

  if (!/^[a-z0-9][a-z0-9-]{1,31}$/.test(body.name)) {
    throw new HttpError(
      400,
      "Name must be 2-32 chars, lowercase alphanumeric and hyphens, starting with alphanumeric"
    );
  }

  const visibility = (body.visibility === "public" ? "public" : "private");

  const existing = await env.DB
    .prepare("SELECT id FROM agents WHERE name = ?")
    .bind(body.name)
    .first<{ id: string }>();

  if (existing) {
    throw new HttpError(409, `Name '${body.name}' is already taken`);
  }

  const id = generateId();
  const apiKey = generateApiKey();
  const webhookUrl = body.webhook_url ?? null;
  const publicKeyPem = body.public_key_pem ?? null;
  const manifest = body.manifest ? JSON.stringify(body.manifest) : null;

  if (webhookUrl) {
    try {
      new URL(webhookUrl);
    } catch {
      throw new HttpError(400, "Invalid webhook_url — must be a valid URL");
    }
  }

  await env.DB
    .prepare(
      "INSERT INTO agents (id, name, api_key, webhook_url, visibility, public_key_pem, manifest) VALUES (?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(id, body.name, apiKey, webhookUrl, visibility, publicKeyPem, manifest)
    .run();

  return jsonResponse({
    agent_id: id,
    name: body.name,
    api_key: apiKey,
    webhook_url: webhookUrl,
    visibility: visibility,
    message: "Agent registered. Save your api_key — it won't be shown again!",
  });
}

// Check if sender is allowed to message the target
// Returns: { allowed: true } or { allowed: false, reason: string }
async function checkMessagePermission(
  senderId: string,
  target: Agent,
  db: D1Database
): Promise<{ allowed: boolean; reason?: string }> {
  // Public agents can be messaged by anyone
  if (target.visibility === "public") {
    return { allowed: true };
  }

  // Can't message yourself (but it's allowed, just odd)
  if (senderId === target.id) {
    return { allowed: true };
  }

  // Check if sender has target in their contacts allowlist
  // (i.e., "I added you as a contact" means "I can message you")
  const contact = await db
    .prepare(
      "SELECT contact_agent_id FROM contacts WHERE agent_id = ? AND contact_agent_id = ?"
    )
    .bind(senderId, target.id)
    .first<{ contact_agent_id: string }>();

  if (contact) {
    return { allowed: true };
  }

  return { allowed: false, reason: `Agent '${target.name}' is private and you have not added them as a contact` };
}

// Server-side rate limiting: counts messages in D1 (not KV) to stay within KV free tier.
// D1 free tier: 50,000 reads/day. KV free tier: 1,000 reads/day.
async function checkOutboundRateLimit(
  agentId: string,
  env: Env,
  limit: number = MAX_OUTBOUND_PER_HOUR
): Promise<boolean> {
  const oneHourAgo = new Date(Date.now() - 3600000).toISOString();
  const result = await env.DB
    .prepare(
      "SELECT COUNT(*) as count FROM messages WHERE from_agent_id = ? AND created_at >= ?"
    )
    .bind(agentId, oneHourAgo)
    .first<{ count: number }>();

  return (result?.count ?? 0) < limit;
}

async function handleSend(request: Request, env: Env): Promise<Response> {
  const sender = await authenticateAgent(request.headers, env.DB);

  // Server-side rate limit check
  const withinLimit = await checkOutboundRateLimit(sender.id, env);
  if (!withinLimit) {
    throw new HttpError(429, `Rate limit exceeded. Maximum ${MAX_OUTBOUND_PER_HOUR} messages per hour.`);
  }
  const body = (await request.json()) as SendRequest;

  if (!body?.to || typeof body.to !== "string") {
    throw new HttpError(400, "Missing or invalid 'to' field (target agent name)");
  }
  if (!body?.payload) {
    throw new HttpError(400, "Missing 'payload' field");
  }

  const target = await env.DB
    .prepare("SELECT * FROM agents WHERE name = ?")
    .bind(body.to)
    .first<Agent>();

  if (!target) {
    throw new HttpError(404, `Agent '${body.to}' not found`);
  }

  // Check permission: is sender allowed to message this target?
  const permission = await checkMessagePermission(sender.id, target, env.DB);

  const messageId = generateId();
  const baseUrl = new URL(request.url);
  baseUrl.search = "";
  // Reply endpoint is at /send/reply/{id}
  const replyTo = `/send/reply/${messageId}`;

  // If not allowed, mark as spam
  const status = permission.allowed ? "queued" : "spam";

  // Compute expires_at from ttl_seconds
  let expiresAt: string | null = null;
  if (body.ttl_seconds != null) {
    const ttl = Math.max(MIN_TTL_SECONDS, Math.min(MAX_TTL_SECONDS, body.ttl_seconds));
    expiresAt = new Date(Date.now() + ttl * 1000).toISOString();
  }

  await env.DB
    .prepare(
      "INSERT INTO messages (id, from_agent_id, to_agent_id, type, payload, reply_to, status, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(
      messageId,
      sender.id,
      target.id,
      body.type ?? "message",
      JSON.stringify(body.payload),
      replyTo,
      status,
      expiresAt
    )
    .run();

  // Only deliver non-spam messages immediately
  if (permission.allowed) {
    // Fire SSE event for real-time delivery
    await fireSseEvent(target.id, messageId, body.type ?? "message", env);

    const message = await env.DB
      .prepare("SELECT * FROM messages WHERE id = ?")
      .bind(messageId)
      .first<Message>();

    if (message) {
      deliverMessage(message, env);
    }
  }

  if (!permission.allowed) {
    return jsonResponse({
      message_id: messageId,
      to: body.to,
      status: "blocked",
      reason: permission.reason,
      reply_to: replyTo,
    }, 403);
  }

  return jsonResponse({
    message_id: messageId,
    to: body.to,
    status: "queued",
    reply_to: replyTo,
  });
}

async function handleInbox(request: Request, env: Env): Promise<Response> {
  const agent = await authenticateAgent(request.headers, env.DB);

  const url = new URL(request.url);
  const limit = Math.min(parseInt(url.searchParams.get("limit") ?? "20"), 100);
  const includeSpam = url.searchParams.get("include_spam") === "true";
  const includeDelivered = url.searchParams.get("include_delivered") === "true";

  // Fetch normal messages (queued)
  let statuses = ["queued"];
  if (includeSpam) {
    statuses.push("spam");
  }
  if (includeDelivered) {
    statuses.push("delivered");
  }

  const statusPlaceholders = statuses.map(() => "?").join(",");
  const result = await env.DB
    .prepare(
      "SELECT m.*, a.name as from_name FROM messages m " +
        "JOIN agents a ON m.from_agent_id = a.id " +
        `WHERE m.to_agent_id = ? AND m.status IN (${statusPlaceholders}) ` +
        "AND (m.expires_at IS NULL OR m.expires_at > strftime('%Y-%m-%dT%H:%M:%fZ', 'now')) " +
        "ORDER BY m.created_at DESC LIMIT ?"
    )
    .bind(agent.id, ...statuses.map(s => s as string), limit)
    .all<Record<string, unknown>>();

  // Batch-update all queued messages to delivered in a single query
  const queuedIds = result.results
    .filter(m => m.status === "queued")
    .map(m => m.id as string);

  if (queuedIds.length > 0) {
    const now = new Date().toISOString();
    const placeholders = queuedIds.map(() => "?").join(",");
    await env.DB
      .prepare(
        `UPDATE messages SET status = 'delivered', delivered_at = ? WHERE id IN (${placeholders})`
      )
      .bind(now, ...queuedIds)
      .run();
  }

  const inbox: InboxMessage[] = result.results.map((m) => ({
    id: m.id as string,
    from: m.from_name as string,
    type: m.type as string,
    payload: JSON.parse(m.payload as string),
    reply_to: m.reply_to as string | null,
    spam: m.status === "spam",
    read: m.status === "delivered",
    created_at: m.created_at as string,
    expires_at: m.expires_at as string | null,
  }));

  return jsonResponse({ messages: inbox });
}

async function handleReply(
  request: Request,
  env: Env,
  messageId: string
): Promise<Response> {
  const sender = await authenticateAgent(request.headers, env.DB);

  const original = await env.DB
    .prepare("SELECT * FROM messages WHERE id = ?")
    .bind(messageId)
    .first<Message>();

  if (!original) {
    throw new HttpError(404, "Message not found");
  }

  if (sender.id !== original.to_agent_id && sender.id !== original.from_agent_id) {
    throw new HttpError(403, "You are not authorized to reply to this message");
  }

  const body = (await request.json()) as { payload: unknown };
  if (!body?.payload) {
    throw new HttpError(400, "Missing 'payload' field");
  }

  const replyId = generateId();
  const replyTo = `/send/reply/${replyId}`;

  await env.DB
    .prepare(
      "INSERT INTO messages (id, from_agent_id, to_agent_id, type, payload, reply_to) VALUES (?, ?, ?, 'reply', ?, ?)"
    )
    .bind(replyId, sender.id, original.from_agent_id, JSON.stringify(body.payload), replyTo)
    .run();

  // Fire SSE event for real-time delivery
  await fireSseEvent(original.from_agent_id, replyId, "reply", env);

  const replyMessage = await env.DB
    .prepare("SELECT * FROM messages WHERE id = ?")
    .bind(replyId)
    .first<Message>();

  if (replyMessage) {
    deliverMessage(replyMessage, env);
  }

  return jsonResponse({
    message_id: replyId,
    to: original.from_agent_id,
    status: "queued",
  });
}

async function handleAgents(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const query = url.searchParams.get("q") ?? "";
  const page = Math.max(1, parseInt(url.searchParams.get("page") ?? "1"));
  const pageSize = Math.min(
    Math.max(1, parseInt(url.searchParams.get("limit") ?? String(AGENTS_PAGE_SIZE))),
    MAX_AGENTS_PAGE_SIZE
  );
  const offset = (page - 1) * pageSize;

  // Simple KV cache for the agents directory (600s TTL — minimized KV reads)
  const cacheKey = `agents-cache:${query || "all"}:${page}:${pageSize}`;
  const cached = await env.RATE_LIMIT.get(cacheKey);
  if (cached) {
    const parsed = JSON.parse(cached);
    // Short TTL to avoid stale data; still saves DB reads
    return new Response(JSON.stringify(parsed, null, 2), {
      status: 200,
      headers: { "Content-Type": "application/json", "X-Cache": "HIT" },
    });
  }

  let result: D1Result<Agent>;
  let totalCount: number;

  if (query) {
    // Search by name, description (in manifest JSON), capabilities, and tags
    const searchPattern = `%${query}%`;
    result = await env.DB
      .prepare(
        "SELECT id, name, visibility, manifest, created_at FROM agents " +
        "WHERE name LIKE ? OR manifest LIKE ? " +
        "ORDER BY created_at DESC LIMIT ? OFFSET ?"
      )
      .bind(searchPattern, searchPattern, pageSize, offset)
      .all<Agent>();

    // Get total count for pagination metadata
    const countResult = await env.DB
      .prepare(
        "SELECT COUNT(*) as count FROM agents " +
        "WHERE name LIKE ? OR manifest LIKE ?"
      )
      .bind(searchPattern, searchPattern)
      .first<{ count: number }>();
    totalCount = countResult?.count ?? 0;
  } else {
    result = await env.DB
      .prepare(
        "SELECT id, name, visibility, manifest, created_at FROM agents ORDER BY created_at DESC LIMIT ? OFFSET ?"
      )
      .bind(pageSize, offset)
      .all<Agent>();

    // Get total count for pagination metadata
    const countResult = await env.DB
      .prepare("SELECT COUNT(*) as count FROM agents")
      .first<{ count: number }>();
    totalCount = countResult?.count ?? 0;
  }

  const response = {
    agents: result.results.map((a) => ({
      id: a.id,
      name: a.name,
      visibility: a.visibility,
      manifest: a.manifest ? JSON.parse(a.manifest) as AgentManifest : null,
      created_at: a.created_at,
    })),
    query: query || null,
    pagination: {
      page,
      page_size: pageSize,
      total: totalCount,
      total_pages: Math.ceil(totalCount / pageSize),
    },
  };

  // Cache the result for 600 seconds (10 minutes — minimizes KV reads)
  await env.RATE_LIMIT.put(cacheKey, JSON.stringify(response), { expirationTtl: 600 });

  return jsonResponse(response);
}

async function handleAgentInfo(
  _request: Request,
  env: Env,
  name: string
): Promise<Response> {
  const agent = await env.DB
    .prepare("SELECT id, name, visibility, public_key_pem, manifest, created_at FROM agents WHERE name = ?")
    .bind(name)
    .first<Agent>();

  if (!agent) {
    throw new HttpError(404, `Agent '${name}' not found`);
  }

  return jsonResponse({
    id: agent.id,
    name: agent.name,
    visibility: agent.visibility,
    public_key_pem: agent.public_key_pem,
    manifest: agent.manifest ? JSON.parse(agent.manifest) as AgentManifest : null,
    created_at: agent.created_at,
  });
}

// --- Manifest endpoint (PUT to set/update agent manifest) ---

async function handleAgentManifest(
  request: Request,
  env: Env,
  name: string
): Promise<Response> {
  const agent = await authenticateAgent(request.headers, env.DB);

  const target = await env.DB
    .prepare("SELECT id, name FROM agents WHERE name = ?")
    .bind(name)
    .first<Agent>();

  if (!target) {
    throw new HttpError(404, `Agent '${name}' not found`);
  }

  // Only the agent themselves can update their manifest
  if (agent.id !== target.id) {
    throw new HttpError(403, `You can only update your own manifest`);
  }

  const body = (await request.json()) as AgentManifest;
  const manifestJson = JSON.stringify(body);

  await env.DB
    .prepare("UPDATE agents SET manifest = ? WHERE id = ?")
    .bind(manifestJson, agent.id)
    .run();

  return jsonResponse({
    name: agent.name,
    manifest: body,
    message: `Manifest updated for '${agent.name}'`,
  });
}

// --- Public Key endpoint (for E2EE) ---

async function handleAgentPublicKey(
  _request: Request,
  env: Env,
  name: string
): Promise<Response> {
  const agent = await env.DB
    .prepare("SELECT name, public_key_pem FROM agents WHERE name = ?")
    .bind(name)
    .first<Agent>();

  if (!agent) {
    throw new HttpError(404, `Agent '${name}' not found`);
  }

  if (!agent.public_key_pem) {
    throw new HttpError(404, `Agent '${name}' has no public key registered (may need to re-register)`);
  }

  return jsonResponse({
    name: agent.name,
    public_key_pem: agent.public_key_pem,
  });
}

// --- Contacts endpoints ---

async function handleContactsList(
  request: Request,
  env: Env
): Promise<Response> {
  const agent = await authenticateAgent(request.headers, env.DB);

  const result = await env.DB
    .prepare(
      "SELECT a.id, a.name, a.visibility, c.created_at " +
        "FROM contacts c " +
        "JOIN agents a ON c.contact_agent_id = a.id " +
        "WHERE c.agent_id = ? " +
        "ORDER BY a.name ASC"
    )
    .bind(agent.id)
    .all<Record<string, unknown>>();

  return jsonResponse({
    contacts: result.results.map((r) => ({
      id: r.id as string,
      name: r.name as string,
      visibility: r.visibility as string,
      added_at: r.created_at as string,
    })),
  });
}

async function handleContactAdd(
  request: Request,
  env: Env
): Promise<Response> {
  const agent = await authenticateAgent(request.headers, env.DB);
  const body = (await request.json()) as { agent_name: string };

  if (!body?.agent_name || typeof body.agent_name !== "string") {
    throw new HttpError(400, "Missing or invalid 'agent_name' field");
  }

  const target = await env.DB
    .prepare("SELECT id FROM agents WHERE name = ?")
    .bind(body.agent_name)
    .first<{ id: string }>();

  if (!target) {
    throw new HttpError(404, `Agent '${body.agent_name}' not found`);
  }

  // Check if already a contact
  const existing = await env.DB
    .prepare(
      "SELECT contact_agent_id FROM contacts WHERE agent_id = ? AND contact_agent_id = ?"
    )
    .bind(agent.id, target.id)
    .first<{ contact_agent_id: string }>();

  if (existing) {
    throw new HttpError(409, `'${body.agent_name}' is already in your contacts`);
  }

  // Add target to this agent's contacts
  await env.DB
    .prepare(
      "INSERT INTO contacts (agent_id, contact_agent_id) VALUES (?, ?)"
    )
    .bind(agent.id, target.id)
    .run();

  // Also add this agent to target's contacts (bidirectional consent)
  // If A requests contact with B and B accepts, both can message each other
  const reverseContact = await env.DB
    .prepare(
      "SELECT contact_agent_id FROM contacts WHERE agent_id = ? AND contact_agent_id = ?"
    )
    .bind(target.id, agent.id)
    .first<{ contact_agent_id: string }>();

  if (!reverseContact) {
    await env.DB
      .prepare(
        "INSERT INTO contacts (agent_id, contact_agent_id) VALUES (?, ?)"
      )
      .bind(target.id, agent.id)
      .run();
  }

  return jsonResponse({
    message: `Added '${body.agent_name}' to your contacts (bidirectional)`,
    agent_id: target.id,
    agent_name: body.agent_name,
  });
}

async function handleContactRemove(
  request: Request,
  env: Env
): Promise<Response> {
  const agent = await authenticateAgent(request.headers, env.DB);
  const body = (await request.json()) as { agent_name: string };

  if (!body?.agent_name || typeof body.agent_name !== "string") {
    throw new HttpError(400, "Missing or invalid 'agent_name' field");
  }

  const target = await env.DB
    .prepare("SELECT id FROM agents WHERE name = ?")
    .bind(body.agent_name)
    .first<{ id: string }>();

  if (!target) {
    throw new HttpError(404, `Agent '${body.agent_name}' not found`);
  }

  const result = await env.DB
    .prepare(
      "DELETE FROM contacts WHERE agent_id = ? AND contact_agent_id = ?"
    )
    .bind(agent.id, target.id)
    .run();

  if (!result.success) {
    throw new HttpError(404, `'${body.agent_name}' is not in your contacts`);
  }

  // Also remove this agent from target's contacts (bidirectional removal)
  await env.DB
    .prepare(
      "DELETE FROM contacts WHERE agent_id = ? AND contact_agent_id = ?"
    )
    .bind(target.id, agent.id)
    .run();

  return jsonResponse({
    message: `Removed '${body.agent_name}' from your contacts (bidirectional)`,
  });
}

// --- Handshake endpoint ---
// Lets agents request to contact each other with server-enforced rate limiting.
// 1 handshake per pair per 24h (KV), 1 lifetime per pair (D1).

async function handleHandshake(request: Request, env: Env): Promise<Response> {
  const sender = await authenticateAgent(request.headers, env.DB);
  const body = (await request.json()) as { agent_name: string };

  if (!body?.agent_name || typeof body.agent_name !== "string") {
    throw new HttpError(400, "Missing or invalid 'agent_name' field");
  }

  const target = await env.DB
    .prepare("SELECT id, name, visibility FROM agents WHERE name = ?")
    .bind(body.agent_name)
    .first<Agent>();

  if (!target) {
    throw new HttpError(404, `Agent '${body.agent_name}' not found`);
  }

  if (sender.id === target.id) {
    throw new HttpError(400, "Cannot send a handshake to yourself");
  }

  // 1. Per-agent daily spam limit — max handshakes per day from one agent
  const todayStart = new Date();
  todayStart.setHours(0, 0, 0, 0);
  const dailyCountResult = await env.DB
    .prepare(
      "SELECT COUNT(*) as count FROM handshakes WHERE from_agent_id = ? AND created_at >= ?"
    )
    .bind(sender.id, todayStart.toISOString())
    .first<{ count: number }>();

  const dailyCount = dailyCountResult?.count ?? 0;
  if (dailyCount >= MAX_HANDSHAKES_PER_DAY) {
    return jsonResponse({
      error: `Daily handshake limit exceeded. Maximum ${MAX_HANDSHAKES_PER_DAY} handshakes per day. (${dailyCount} used today)`,
      status: "daily_limit",
    }, 429);
  }

  // 2. Lifetime check — has a handshake already been attempted between this pair?
  const history = await env.DB
    .prepare(
      "SELECT id FROM handshakes WHERE from_agent_id = ? AND to_agent_id = ? LIMIT 1"
    )
    .bind(sender.id, target.id)
    .first<Record<string, unknown>>();

  if (history) {
    return jsonResponse({
      error: "A handshake request has already been attempted between these agents.",
      status: "already_attempted",
    }, 403);
  }

  // 3. 24-hour cooldown check via KV
  const cacheKey = `handshake:${sender.id}:${target.id}`;
  const existingLock = await env.RATE_LIMIT.get(cacheKey);

  if (existingLock) {
    return jsonResponse({
      error: "Handshake cooldown active. You can only attempt contact once every 24 hours.",
      status: "cooldown",
    }, 429);
  }

  // 4. Log the handshake in D1 (lifetime record)
  await env.DB
    .prepare(
      "INSERT INTO handshakes (id, from_agent_id, to_agent_id, status, created_at) VALUES (?, ?, ?, ?, ?)"
    )
    .bind(generateId(), sender.id, target.id, "pending", new Date().toISOString())
    .run();

  // 5. Set 24-hour TTL in KV to prevent spam
  await env.RATE_LIMIT.put(cacheKey, "locked", { expirationTtl: HANDSHAKE_COOLDOWN_SECONDS });

  // 6. Drop a handshake message in the recipient's inbox
  const messageId = generateId();
  const replyTo = `/send/reply/${messageId}`;

  await env.DB
    .prepare(
      "INSERT INTO messages (id, from_agent_id, to_agent_id, type, payload, reply_to, status) VALUES (?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(
      messageId,
      sender.id,
      target.id,
      "handshake",
      JSON.stringify({
        message: `${sender.name} would like to contact you. Add them as a contact to allow messages.`,
        sender_name: sender.name,
        sender_public_key_pem: sender.public_key_pem,
      }),
      replyTo,
      "queued"
    )
    .run();

  // Fire SSE event for real-time delivery
  await fireSseEvent(target.id, messageId, "handshake", env);

  // Deliver via webhook if target has one
  const replyMessage = await env.DB
    .prepare("SELECT * FROM messages WHERE id = ?")
    .bind(messageId)
    .first<Message>();

  if (replyMessage) {
    deliverMessage(replyMessage, env);
  }

  return jsonResponse({
    message_id: messageId,
    to: body.agent_name,
    status: "pending",
    reply_to: replyTo,
    daily_handshake_count: dailyCount + 1,
    daily_handshake_limit: MAX_HANDSHAKES_PER_DAY,
    message: `Handshake request sent to '${body.agent_name}'. They will receive a notification.`,
  });
}

// --- Scheduled cleanup: purge old messages + SSE events to prevent unbounded DB growth ---

export const scheduled: ExportedHandler<Env>["scheduled"] = async (_controller, env): Promise<void> => {
  const now = new Date().toISOString();
  const deliveredCutoff = new Date(Date.now() - MESSAGE_RETENTION_DAYS * 86400000).toISOString();
  const failedCutoff = new Date(Date.now() - FAILED_MESSAGE_RETENTION_DAYS * 86400000).toISOString();

  // Delete old delivered messages
  const deliveredDeleted = await env.DB
    .prepare("DELETE FROM messages WHERE status = 'delivered' AND delivered_at < ?")
    .bind(deliveredCutoff)
    .run();

  // Delete old permanently failed messages
  const failedDeleted = await env.DB
    .prepare("DELETE FROM messages WHERE status = 'failed' AND created_at < ?")
    .bind(failedCutoff)
    .run();

  // Delete TTL-expired messages (expires_at is set but has passed)
  const expiredDeleted = await env.DB
    .prepare("DELETE FROM messages WHERE expires_at IS NOT NULL AND expires_at <= strftime('%Y-%m-%dT%H:%M:%fZ', 'now')")
    .run();

  // Delete old SSE events (older than 5 minutes — clients should have picked them up by now)
  const sseCutoff = new Date(Date.now() - 5 * 60 * 1000).toISOString();
  const sseDeleted = await env.DB
    .prepare("DELETE FROM sse_events WHERE created_at < ?")
    .bind(sseCutoff)
    .run();

  console.log(
    `Cleanup: deleted ${deliveredDeleted.results?.length ?? 0} delivered, ` +
    `${failedDeleted.results?.length ?? 0} failed, ` +
    `${expiredDeleted.results?.length ?? 0} expired messages, ` +
    `${sseDeleted.results?.length ?? 0} SSE events (as of ${now})`
  );
};

// --- Request Router ---

async function handleRequest(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const method = request.method;
  const path = url.pathname;

  if (method === "OPTIONS") {
    return new Response(null, {
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
      },
    });
  }

  // Enforce maximum request body size on all mutating endpoints
  if (method === "POST") {
    const contentLength = parseInt(request.headers.get("Content-Length") ?? "0", 10);
    if (contentLength > MAX_REQUEST_BODY_BYTES) {
      return jsonResponse({ error: `Payload too large. Maximum ${MAX_REQUEST_BODY_BYTES} bytes.` }, 413);
    }
  }

  try {
    let response: Response;

    if (path === "/register" && method === "POST") {
      response = await handleRegister(request, env);
    } else if (path === "/send" && method === "POST") {
      response = await handleSend(request, env);
    } else if (path === "/stream" && method === "GET") {
      response = await handleSseStream(request, env);
    } else if (path === "/inbox" && method === "GET") {
      response = await handleInbox(request, env);
    } else if (path === "/agents" && method === "GET") {
      response = await handleAgents(request, env);
    } else if (path.match(/^\/agent\/.+\/public-key$/) && method === "GET") {
      const name = decodeURIComponent(path.split("/")[2]);
      response = await handleAgentPublicKey(request, env, name);
    } else if (path.match(/^\/agent\/.+\/manifest$/) && method === "PUT") {
      const name = decodeURIComponent(path.split("/")[2]);
      response = await handleAgentManifest(request, env, name);
    } else if (path.match(/^\/agent\/.+$/) && method === "GET") {
      const name = decodeURIComponent(path.split("/")[2]);
      response = await handleAgentInfo(request, env, name);
    } else if (path.match(/^\/send\/reply\/.+$/) && method === "POST") {
      const messageId = decodeURIComponent(path.split("/")[3]);
      response = await handleReply(request, env, messageId);
    } else if (path === "/contacts" && method === "GET") {
      response = await handleContactsList(request, env);
    } else if (path === "/contacts" && method === "POST") {
      response = await handleContactAdd(request, env);
    } else if (path === "/contacts" && method === "DELETE") {
      response = await handleContactRemove(request, env);
    } else if (path === "/handshake" && method === "POST") {
      response = await handleHandshake(request, env);
    } else if (path === "/" && method === "GET") {
      response = jsonResponse({
        name: "OpenMyna Switchboard",
        version: "0.6.0-ttl",
        endpoints: {
          "POST /register": "Register a new agent (accepts public_key_pem for E2EE)",
          "POST /send": "Send a message to another agent (payload can be encrypted blob; supports ttl_seconds)",
          "GET /stream": "SSE stream for real-time message delivery (use ?cursor=N for resumption)",
          "GET /inbox": "Poll for messages (returns encrypted payloads; filters expired TTL messages)",
          "POST /send/reply/{messageId}": "Reply to a message",
          "GET /agents": "List all registered agents (use ?q=search for discovery)",
          "GET /agent/{name}": "Get agent info (includes public_key_pem, manifest)",
          "PUT /agent/{name}/manifest": "Set/update agent manifest (capabilities, description, tags)",
          "GET /agent/{name}/public-key": "Get agent's public key for E2EE",
          "GET /contacts": "List your contacts",
          "POST /contacts": "Add a contact",
          "DELETE /contacts": "Remove a contact",
          "POST /handshake": "Request contact with another agent (rate-limited, includes sender public key)",
        },
      });
    } else {
      throw new HttpError(404, "Not found");
    }

    response.headers.set("Access-Control-Allow-Origin", "*");
    return response;
  } catch (err) {
    if (err instanceof HttpError) {
      return jsonResponse({ error: err.message }, err.status);
    }
    console.error("Unexpected error:", err);
    return jsonResponse({ error: "Internal server error" }, 500);
  }
}

// --- Export ---

// --- Export ---

export default {
  fetch: handleRequest,
  scheduled,
} satisfies ExportedHandler<Env>;
