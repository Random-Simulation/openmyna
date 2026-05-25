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
}

interface SendRequest {
  to: string;
  type?: string;
  payload: unknown;
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
}

// --- Bindings ---

interface Env {
  DB: D1Database;
  RATE_LIMIT: KVNamespace;
}

// --- Constants ---

const MAX_REQUEST_BODY_BYTES = 102400; // 100KB gross request cap
const HANDSHAKE_COOLDOWN_SECONDS = 86400; // 24 hours

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

async function handleSend(request: Request, env: Env): Promise<Response> {
  const sender = await authenticateAgent(request.headers, env.DB);
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

  await env.DB
    .prepare(
      "INSERT INTO messages (id, from_agent_id, to_agent_id, type, payload, reply_to, status) VALUES (?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(
      messageId,
      sender.id,
      target.id,
      body.type ?? "message",
      JSON.stringify(body.payload),
      replyTo,
      status
    )
    .run();

  // Only deliver non-spam messages immediately
  if (permission.allowed) {
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
        "ORDER BY m.created_at DESC LIMIT ?"
    )
    .bind(agent.id, ...statuses.map(s => s as string), limit)
    .all<Record<string, unknown>>();

  if (result.results.length > 0) {
    const now = new Date().toISOString();
    for (const msg of result.results) {
      // Mark queued as delivered, but leave spam as spam
      if (msg.status === "queued") {
        await env.DB
          .prepare(
            "UPDATE messages SET status = 'delivered', delivered_at = ? WHERE id = ?"
          )
          .bind(now, msg.id as string)
          .run();
      }
    }
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

  let result: D1Result<Agent>;
  if (query) {
    // Search by name, description (in manifest JSON), capabilities, and tags
    const searchPattern = `%${query}%`;
    result = await env.DB
      .prepare(
        "SELECT id, name, visibility, manifest, created_at FROM agents " +
        "WHERE name LIKE ? OR manifest LIKE ? " +
        "ORDER BY created_at DESC"
      )
      .bind(searchPattern, searchPattern)
      .all<Agent>();
  } else {
    result = await env.DB
      .prepare("SELECT id, name, visibility, manifest, created_at FROM agents ORDER BY created_at DESC")
      .all<Agent>();
  }

  return jsonResponse({
    agents: result.results.map((a) => ({
      id: a.id,
      name: a.name,
      visibility: a.visibility,
      manifest: a.manifest ? JSON.parse(a.manifest) as AgentManifest : null,
      created_at: a.created_at,
    })),
    query: query || null,
    total: result.results.length,
  });
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

  // 1. Lifetime check — has a handshake already been attempted between this pair?
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

  // 2. 24-hour cooldown check via KV
  const cacheKey = `handshake:${sender.id}:${target.id}`;
  const existingLock = await env.RATE_LIMIT.get(cacheKey);

  if (existingLock) {
    return jsonResponse({
      error: "Handshake cooldown active. You can only attempt contact once every 24 hours.",
      status: "cooldown",
    }, 429);
  }

  // 3. Log the handshake in D1 (lifetime record)
  await env.DB
    .prepare(
      "INSERT INTO handshakes (id, from_agent_id, to_agent_id, status, created_at) VALUES (?, ?, ?, ?, ?)"
    )
    .bind(generateId(), sender.id, target.id, "pending", new Date().toISOString())
    .run();

  // 4. Set 24-hour TTL in KV to prevent spam
  await env.RATE_LIMIT.put(cacheKey, "locked", { expirationTtl: HANDSHAKE_COOLDOWN_SECONDS });

  // 5. Drop a handshake message in the recipient's inbox
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
    message: `Handshake request sent to '${body.agent_name}'. They will receive a notification.`,
  });
}

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
        version: "0.4.0-manifest",
        endpoints: {
          "POST /register": "Register a new agent (accepts public_key_pem for E2EE)",
          "POST /send": "Send a message to another agent (payload can be encrypted blob)",
          "GET /inbox": "Poll for messages (returns encrypted payloads)",
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

export default {
  fetch: handleRequest,
} satisfies ExportedHandler<Env>;
