#!/usr/bin/env -S npx tsx
/**
 * Demo script: simulates two agents registering and exchanging messages.
 * Run with: npx tsx scripts/demo.ts
 *
 * Requires the switchboard running locally (wrangler dev) or at a URL.
 */

const BASE_URL = process.env.OPENMYNA_URL ?? "http://localhost:8787";

async function api(path: string, options: RequestInit = {}): Promise<unknown> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...options.headers as Record<string, string>,
  };

  const resp = await fetch(`${BASE_URL}${path}`, { ...options, headers });
  const data = await resp.json();

  if (!resp.ok) {
    console.error(`❌ ${resp.status} ${path}:`, data);
    throw new Error(`${resp.status} ${path}: ${JSON.stringify(data)}`);
  }

  return data;
}

async function main() {
  console.log(`\n🐦 OpenMyna Switchboard Demo\n${"=".repeat(40)}\n`);
  console.log(`Target: ${BASE_URL}\n`);

  // --- Register two agents ---
  console.log("1️⃣  Registering agents...");

  const alice = (await api("/register", {
    method: "POST",
    body: JSON.stringify({
      name: "alice",
      webhook_url: "http://localhost:9999/alice", // hypothetical webhook
    }),
  })) as Record<string, unknown>;

  const bob = (await api("/register", {
    method: "POST",
    body: JSON.stringify({
      name: "bob",
      webhook_url: "http://localhost:9999/bob",
    }),
  })) as Record<string, unknown>;

  console.log(`   ✅ Alice: ${alice.agent_id} (key: ${alice.api_key})`);
  console.log(`   ✅ Bob:   ${bob.agent_id} (key: ${bob.api_key})\n`);

  // --- Alice sends Bob a message ---
  console.log("2️⃣  Alice sends Bob a message...");

  const sent = (await api("/send", {
    method: "POST",
    headers: { Authorization: `Bearer ${alice.api_key}` },
    body: JSON.stringify({
      to: "bob",
      payload: {
        text: "Hey Bob! Want to grab coffee?",
        action: "invite",
      },
    }),
  })) as Record<string, unknown>;

  console.log(`   📨 Message ${sent.message_id} → bob (${sent.status})`);
  console.log(`   📬 Reply-to: ${sent.reply_to}\n`);

  // --- Bob checks inbox ---
  console.log("3️⃣  Bob checks inbox...");

  const inbox = (await api("/inbox", {
    headers: { Authorization: `Bearer ${bob.api_key}` },
  })) as { messages: unknown[] };

  console.log(`   📬 ${inbox.messages.length} message(s):\n`);
  for (const msg of inbox.messages as Record<string, unknown>[]) {
    console.log(`   From: ${msg.from}`);
    console.log(`   Type: ${msg.type}`);
    console.log(`   Payload: ${JSON.stringify(msg.payload)}`);
    console.log(`   ID: ${msg.id}\n`);
  }

  // --- Bob replies ---
  console.log("4️⃣  Bob replies...");

  const reply = (await api(`/send/reply/${inbox.messages[0]!.id}`, {
    method: "POST",
    headers: { Authorization: `Bearer ${bob.api_key}` },
    body: JSON.stringify({
      payload: {
        text: "Sure! How about 3pm at the usual place?",
        action: "accept",
      },
    }),
  })) as Record<string, unknown>;

  console.log(`   📨 Reply ${reply.message_id} → alice (${reply.status})\n`);

  // --- Alice checks inbox ---
  console.log("5️⃣  Alice checks inbox...");

  const aliceInbox = (await api("/inbox", {
    headers: { Authorization: `Bearer ${alice.api_key}` },
  })) as { messages: unknown[] };

  console.log(`   📬 ${aliceInbox.messages.length} message(s):\n`);
  for (const msg of aliceInbox.messages as Record<string, unknown>[]) {
    console.log(`   From: ${msg.from}`);
    console.log(`   Type: ${msg.type}`);
    console.log(`   Payload: ${JSON.stringify(msg.payload)}`);
    console.log();
  }

  // --- List agents ---
  console.log("6️⃣  Agent directory:");

  const directory = (await api("/agents")) as { agents: unknown[] };
  for (const agent of directory.agents as Record<string, unknown>[]) {
    console.log(`   ${agent.name} (${agent.id})`);
  }

  console.log("\n✅ Demo complete!\n");
}

main().catch(console.error);
