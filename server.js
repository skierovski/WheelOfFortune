// server.js
import 'dotenv/config';
import express from "express";
import bodyParser from "body-parser";
import { WebSocketServer } from "ws";
import http from "http";
import path from "path";
import fs from "fs";
import crypto from "crypto";
import { fileURLToPath } from "url";
import { KickAuthClient } from "kick-auth";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.set("trust proxy", 1);

// Access log
app.use((req, res, next) => {
  const start = Date.now();
  const ua = req.get("user-agent") || "";
  const ip = req.ip;
  console.log(`[REQ] ${req.method} ${req.originalUrl} | ip=${ip} ua="${ua}"`);
  res.on("finish", () => {
    const ms = Date.now() - start;
    console.log(`[RES] ${req.method} ${req.originalUrl} -> ${res.statusCode} (${ms}ms)`);
  });
  next();
});

// ---- Config / env ----
const PORT_HTTP = Number(process.env.PORT) || 3000;
const PUB = path.join(__dirname, "public");
const TOK_PATH = process.env.TOK_PATH || path.join(process.cwd(), "tokens.json");
const CFG_PATH = process.env.CFG_PATH || "/data/wheel.json";
const ADMIN_KEY = process.env.ADMIN_KEY || "";
const WEBHOOK_SECRET = process.env.KICK_WEBHOOK_SECRET || process.env.WEBHOOK_SECRET || "dev_webhook_secret";

// Helper: base URL
function getBaseUrl(req) {
  const proto = (req.headers["x-forwarded-proto"] || req.protocol || "http").split(",")[0].trim();
  const host  = (req.headers["x-forwarded-host"]  || req.get("host")).split(",")[0].trim();
  return `${proto}://${host}`;
}

// CSP
app.use((req, res, next) => {
  res.setHeader("Content-Security-Policy", [
    "default-src 'self' data: blob:",
    "connect-src 'self' https: wss: http: ws:",
    "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:",
    "font-src 'self' data:"
  ].join("; "));
  next();
});

/* =======================================================================================
   TOKEN STORE + AUTO REFRESH
   ======================================================================================= */
function mask(v) {
  if (!v || typeof v !== 'string') return v;
  if (v.length <= 8) return v;
  return v.slice(0, 4) + "..." + v.slice(-4);
}
function loadTokens() {
  try { return JSON.parse(fs.readFileSync(TOK_PATH, "utf8")); } catch { return null; }
}
function saveTokens(t) {
  try {
    fs.writeFileSync(TOK_PATH, JSON.stringify(t, null, 2));
    console.log("[tokens] saved:", {
      access_token: mask(t.access_token),
      refresh_token: mask(t.refresh_token),
      expires_at: t.expires_at,
      scope: t.scope,
    });
  } catch (e) { console.error("[tokens] save failed:", e); }
}
function withExpiresAt(tokens) {
  if (!tokens) return null;
  const skewMs = 60_000 * 5;
  if (!tokens.expires_at && Number.isFinite(tokens.expires_in)) {
    tokens.expires_at = Date.now() + (Number(tokens.expires_in) * 1000) - skewMs;
  }
  return tokens;
}

const kickAuthBase = new KickAuthClient({
  clientId:     process.env.KICK_CLIENT_ID     || "YOUR_CLIENT_ID",
  clientSecret: process.env.KICK_CLIENT_SECRET || "YOUR_CLIENT_SECRET",
  redirectUri:  process.env.KICK_REDIRECT_URI  || `http://localhost:${PORT_HTTP}/auth/callback`,
});

async function ensureAccessToken() {
  let tokens = withExpiresAt(loadTokens());
  if (!tokens?.access_token) throw new Error("No tokens stored. Log in via /auth/login");
  const needRefresh = !tokens.expires_at || Date.now() >= tokens.expires_at;
  if (!needRefresh) return tokens.access_token;

  if (typeof kickAuthBase.refreshAccessToken === "function") {
    console.log("[tokens] refreshing via KickAuthClient.refreshAccessToken()");
    const refreshed = await kickAuthBase.refreshAccessToken(tokens.refresh_token);
    const merged = withExpiresAt({ ...tokens, ...refreshed });
    saveTokens(merged);
    return merged.access_token;
  }
  throw new Error("refreshAccessToken() not available on KickAuthClient");
}

/* =======================================================================================
   EVENTS API HELPERS
   ======================================================================================= */
async function listSubscriptions(token) {
  const r = await fetch("https://api.kick.com/public/v1/events/subscriptions", {
    headers: { Authorization: `Bearer ${token}` }
  });
  if (!r.ok) {
    const txt = await r.text().catch(()=> "");
    throw new Error(`list subs failed: ${r.status} ${txt}`);
  }
  return r.json();
}

async function ensureSubscribedDefault(req) {
  const token = await ensureAccessToken();
  const broadcasterId = await getBroadcasterId();
  const callbackUrl = process.env.KICK_WEBHOOK_URL || `${getBaseUrl(req)}/webhook`;

  try {
    const current = await listSubscriptions(token);
    const exists = Array.isArray(current?.data)
      && current.data.some(s =>
          String(s?.event) === "channel.subscription.gifts" &&
          String(s?.broadcaster_user_id) === String(broadcasterId) &&
          String(s?.transport?.callback) === String(callbackUrl)
        );
    if (exists) {
      console.log("[events] subscription already exists");
      return;
    }
  } catch (e) {
    console.warn("[events] list failed (will still try to create):", e.message);
  }

  const payload = {
    event: "channel.subscription.gifts",
    broadcaster_user_id: Number(broadcasterId),
    transport: { method: "webhook", callback: callbackUrl }
  };

  const r = await fetch("https://api.kick.com/public/v1/events/subscriptions", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });

  if (!r.ok) {
    const txt = await r.text().catch(()=> "");
    if (r.status === 409) {
      console.log("[events] subscription already present (409)");
      return;
    }
    throw new Error(`subscribe failed: ${r.status} ${txt}`);
  }

  const out = await r.json().catch(()=> ({}));
  console.log("[events] subscribed:", out);
}

/* =======================================================================================
   WEBHOOK RSA VERIFY + CHALLENGE
   ======================================================================================= */
const KICK_PUBLIC_KEY_PEM = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAq/+l1WnlRrGSolDMA+A8
6rAhMbQGmQ2SapVcGM3zq8ANXjnhDWocMqfWcTd95btDydITa10kDvHzw9WQOqp2
MZI7ZyrfzJuz5nhTPCiJwTwnEtWft7nV14BYRDHvlfqPUaZ+1KR4OCaO/wWIk/rQ
L/TjY0M70gse8rlBkbo2a8rKhu69RQTRsoaf4DVhDPEeSeI5jVrRDGAMGL3cGuyY
6CLKGdjVEM78g3JfYOvDU/RvfqD7L89TZ3iN94jrmWdGz34JNlEI5hqK8dd7C5EF
BEbZ5jgB8s8ReQV8H+MkuffjdAj3ajDDX3DOJMIut1lBrUVD1AaSrGCKHooWoL2e
twIDAQAB
-----END PUBLIC KEY-----`;

const SEEN_IDS = new Set();
const MAX_SEEN = 500;
function rememberId(id) {
  SEEN_IDS.add(id);
  if (SEEN_IDS.size > MAX_SEEN) {
    const it = SEEN_IDS.values().next();
    if (!it.done) SEEN_IDS.delete(it.value);
  }
}

app.post("/webhook", express.raw({ type: "*/*", limit: "2mb" }), async (req, res) => {
  try {
    const msgId   = req.get("Kick-Event-Message-Id");
    const ts      = req.get("Kick-Event-Message-Timestamp");
    const sigB64  = req.get("Kick-Event-Signature");
    const eType   = req.get("Kick-Event-Type");
    if (!msgId || !ts || !sigB64) {
      return res.status(400).send("Missing signature headers");
    }

    const sentAt = Date.parse(ts);
    if (!Number.isFinite(sentAt)) return res.status(400).send("Invalid timestamp");

    const rawBody = Buffer.isBuffer(req.body) ? req.body : Buffer.from(req.body || "");
    const baseStr = `${msgId}.${ts}.${rawBody.toString("utf8")}`;

    const verifier = crypto.createVerify("RSA-SHA256");
    verifier.update(baseStr, "utf8");
    verifier.end();
    const verified = verifier.verify(KICK_PUBLIC_KEY_PEM, sigB64, "base64");
    if (!verified) return res.status(401).send("Invalid signature");
    rememberId(msgId);

    let payload = {};
    try { payload = JSON.parse(rawBody.toString("utf8")); } catch {}
    const type = eType || payload?.type || payload?.event || "unknown";

    if (type === "webhook_callback_verification" && payload?.challenge) {
      return res.json({ challenge: payload.challenge });
    }

    if (type === "channel.subscription.gifts") {
      const { gifter = {}, giftees = [] } = payload || {};
      const count = Array.isArray(giftees) ? giftees.length : Number(payload?.count || 0);
      const spins = Math.floor(count / 5) || (count >= 5 ? 1 : 0);
      if (spins > 0) broadcast({ action: "spin", times: spins });
    }

    return res.status(200).send("ok");
  } catch {
    return res.status(400).send("Bad webhook");
  }
});

/* =======================================================================================
   CONFIG
   ======================================================================================= */
function loadConfigItems() {
  try {
    const raw = fs.readFileSync(CFG_PATH, "utf8");
    const obj = JSON.parse(raw);
    if (Array.isArray(obj?.items)) return obj.items;
  } catch {}
  return null;
}
function saveConfigItems(items) {
  const obj = { items };
  fs.writeFileSync(CFG_PATH, JSON.stringify(obj, null, 2));
}

app.get("/config", (_req, res) => {
  res.json({ ok: true, items: loadConfigItems() });
});
app.post("/config", express.json(), (req, res) => {
  if (!ADMIN_KEY || req.get("X-Admin-Key") !== ADMIN_KEY) {
    return res.status(401).json({ ok: false, error: "Unauthorized" });
  }
  const items = Array.isArray(req.body?.items) ? req.body.items : null;
  if (!items) return res.status(400).json({ ok: false, error: "Missing items[]" });
  saveConfigItems(items);
  broadcast({ type: "config", items });
  res.json({ ok: true });
});

/* =======================================================================================
   OAuth login / callback
   ======================================================================================= */
const oauthStore = new Map();

app.get("/auth/login", async (req, res) => {
  const desiredScopes = [
    "user:read","channel:read","channel:write",
    "chat:write","events:read","events:write"
  ];
  const redirectUri = process.env.KICK_REDIRECT_URI || `${getBaseUrl(req)}/auth/callback`;
  const authClient = new KickAuthClient({
    clientId: process.env.KICK_CLIENT_ID, clientSecret: process.env.KICK_CLIENT_SECRET, redirectUri,
  });
  let { url, state, codeVerifier } = await authClient.getAuthorizationUrl({ scopes: desiredScopes });
  oauthStore.set(state, { codeVerifier, redirectUri });
  res.redirect(url);
});

app.get("/auth/callback", async (req, res) => {
  const { code, state } = req.query;
  const stored = oauthStore.get(state);
  oauthStore.delete(state);

  const authClient = new KickAuthClient({
    clientId: process.env.KICK_CLIENT_ID, clientSecret: process.env.KICK_CLIENT_SECRET, redirectUri: stored.redirectUri,
  });
  const tokens = await authClient.getAccessToken(String(code), stored.codeVerifier);
  const saved = withExpiresAt(tokens);
  saveTokens(saved);

  try { await ensureSubscribedDefault(req); }
  catch (e) { console.warn("[events] ensure subscribe failed:", e.message); }

  res.send("Auth OK. You can close this window.");
});

/* =======================================================================================
   Broadcaster id + chat
   ======================================================================================= */
let CACHED_BROADCASTER_ID = null;
async function getBroadcasterId() {
  if (CACHED_BROADCASTER_ID) return CACHED_BROADCASTER_ID;
  const token = await ensureAccessToken();
  const r = await fetch("https://api.kick.com/public/v1/users", {
    headers: { Authorization: `Bearer ${token}` }
  });
  const data = await r.json();
  const id = data?.data?.[0]?.user_id;
  CACHED_BROADCASTER_ID = Number(id);
  return CACHED_BROADCASTER_ID;
}

async function postChatMessage(content) {
  const token = await ensureAccessToken();
  const broadcasterId = await getBroadcasterId();
  await fetch("https://api.kick.com/public/v1/chat", {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify({ broadcaster_user_id: broadcasterId, content: content.slice(0,500), type: "user" })
  });
}

/* =======================================================================================
   Debug endpoints
   ======================================================================================= */
app.get("/debug/events", async (req, res) => {
  try {
    const token = await ensureAccessToken();
    const data = await listSubscriptions(token);
    res.json({ ok: true, data });
  } catch (e) { res.status(500).json({ ok:false, error:e.message }); }
});
app.post("/debug/events/subscribe", async (req, res) => {
  try { await ensureSubscribedDefault(req); res.json({ ok:true }); }
  catch (e) { res.status(500).json({ ok:false, error:e.message }); }
});

/* =======================================================================================
   HTTP + WS
   ======================================================================================= */
const server = http.createServer(app);
const wss = new WebSocketServer({ noServer: true });
server.on("upgrade", (req, socket, head) => {
  if (req.url !== "/ws") { socket.destroy(); return; }
  wss.handleUpgrade(req, socket, head, (ws) => { wss.emit("connection", ws, req); });
});
wss.on("connection", (ws, req) => {
  console.log("WS client connected:", req.socket.remoteAddress);
  ws.on("close", () => console.log("WS closed"));
});
function broadcast(obj) {
  const msg = JSON.stringify(obj);
  for (const c of wss.clients) if (c.readyState === 1) c.send(msg);
}

server.listen(PORT_HTTP, () => {
  console.log(`HTTP on http://localhost:${PORT_HTTP}`);
  console.log(`WS on    ws://localhost:${PORT_HTTP}/ws`);
});
