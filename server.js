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
const GOALS_PATH = process.env.GOALS_PATH || "/data/goals.json";
const ADMIN_KEY = process.env.ADMIN_KEY || ""; // ustaw w Renderze!
const WEBHOOK_SECRET = process.env.KICK_WEBHOOK_SECRET || process.env.WEBHOOK_SECRET || "dev_webhook_secret";
const KICK_OAUTH_HOST = "https://id.kick.com";

// Helper: bazowy URL (http/https + host)
function getBaseUrl(req) {
  const proto = (req.headers["x-forwarded-proto"] || req.protocol || "http").split(",")[0].trim();
  const host  = (req.headers["x-forwarded-host"]  || req.get("host")).split(",")[0].trim();
  return `${proto}://${host}`;
}

// CSP
app.use((req, res, next) => {
  res.setHeader(
    "Content-Security-Policy",
    [
      "default-src 'self' data: blob:",
      "connect-src 'self' https: wss: http: ws:",
      "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: blob:",
      "font-src 'self' data:"
    ].join("; ")
  );
  next();
});

/* =======================================================================================
   TOKEN STORE + AUTO REFRESH (manualny /oauth/token)
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
  // odświeżaj 15 min przed końcem
  const skewMs = 60_000 * 15;
  if (Number.isFinite(tokens.expires_in)) {
    tokens.expires_at = Date.now() + (Number(tokens.expires_in) * 1000) - skewMs;
  }
  return tokens;
}

function secondsUntilExpiry(t) {
  if (!t?.expires_at) return -Infinity;
  return Math.floor((t.expires_at - Date.now()) / 1000);
}

// Manualny refresh wg dokumentacji Kick
async function refreshAccessTokenManual(refreshToken) {
  const body = new URLSearchParams();
  body.set("grant_type", "refresh_token");
  body.set("client_id", process.env.KICK_CLIENT_ID || "");
  body.set("client_secret", process.env.KICK_CLIENT_SECRET || "");
  body.set("refresh_token", refreshToken || "");

  const r = await fetch(`${KICK_OAUTH_HOST}/oauth/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body
  });
  const text = await r.text();
  if (!r.ok) throw new Error(`refresh failed: ${r.status} ${text}`);

  let json;
  try { json = JSON.parse(text); } catch { throw new Error("refresh parse error"); }

  // spodziewamy się: access_token, refresh_token, expires_in, scope, token_type
  if (!json?.access_token) throw new Error("refresh response missing access_token");
  return json;
}

const kickAuthBase = new KickAuthClient({
  clientId:     process.env.KICK_CLIENT_ID     || "YOUR_CLIENT_ID",
  clientSecret: process.env.KICK_CLIENT_SECRET || "YOUR_CLIENT_SECRET",
  redirectUri:  process.env.KICK_REDIRECT_URI  || `http://localhost:${PORT_HTTP}/auth/callback`,
});

async function ensureAccessToken() {
  let tokens = loadTokens();
  if (!tokens?.access_token) throw new Error("No tokens stored. Log in via /auth/login");

  // jeżeli mamy expires_at i zostało mniej niż 15 min – odśwież
  const secsLeft = secondsUntilExpiry(tokens);
  if (!Number.isFinite(secsLeft) || secsLeft <= 0 || secsLeft <= 15 * 60) {
    if (!tokens.refresh_token) throw new Error("No refresh_token stored");
    console.log(`[tokens] refreshing (left ${secsLeft}s) via manual /oauth/token`);
    const refreshed = await refreshAccessTokenManual(tokens.refresh_token);
    const merged = withExpiresAt({ ...tokens, ...refreshed });
    saveTokens(merged);
    return merged.access_token;
  }

  return tokens.access_token;
}

/* =======================================================================================
   WEBHOOK RSA VERIFY + FULL LOG + CHALLENGE
   ======================================================================================= */

const KICK_PUBLIC_KEY_PEM = `
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAq/+l1WnlRrGSolDMA+A8
6rAhMbQGmQ2SapVcGM3zq8ANXjnhDWocMqfWcTd95btDydITa10kDvHzw9WQOqp2
MZI7ZyrfzJuz5nhTPCiJwTwnEtWft7nV14BYRDHvlfqPUaZ+1KR4OCaO/wWIk/rQ
L/TjY0M70gse8rlBkbo2a8rKhu69RQTRsoaf4DVhDPEeSeI5jVrRDGAMGL3cGuyY
6CLKGdjVEM78g3JfYOvDU/RvfqD7L89TZ3iN94jrmWdGz34JNlEI5hqK8dd7C5EF
BEbZ5jgB8s8ReQV8H+MkuffjdAj3ajDDX3DOJMIut1lBrUVD1AaSrGCKHooWoL2e
twIDAQAB
-----END PUBLIC KEY-----
`.trim();

const SEEN_IDS = new Set();
const MAX_SEEN = 500;
function rememberId(id) {
  SEEN_IDS.add(id);
  if (SEEN_IDS.size > MAX_SEEN) {
    const it = SEEN_IDS.values().next();
    if (!it.done) SEEN_IDS.delete(it.value);
  }
}

app.get("/webhook", (req, res) => {
  console.log("[WEBHOOK][GET] ping", {
    ip: req.ip,
    ua: req.get("user-agent") || null,
    q: req.query
  });
  res.status(200).send("webhook-get-ok");
});

app.head("/webhook", (req, res) => {
  console.log("[WEBHOOK][HEAD] ping", { ip: req.ip, ua: req.get("user-agent") || null });
  res.status(200).end();
});

/* ====== bezstratny licznik spinów (pull & consume) ====== */
let PENDING_SPINS_COUNT = 0;

function addPendingSpins(n) {
  const x = Number(n) || 0;
  if (x > 0) {
    PENDING_SPINS_COUNT += x;
    console.log(`[spins] pending += ${x}  (total=${PENDING_SPINS_COUNT})`);
  }
}

function consumePendingSpins(n) {
  const want = Math.max(0, Number(n) || 0);
  const take = Math.min(PENDING_SPINS_COUNT, want);
  PENDING_SPINS_COUNT -= take;
  console.log(`[spins] consumed ${take}  (left=${PENDING_SPINS_COUNT})`);
  return take;
}

app.get("/spins/pending", (_req, res) => {
  res.json({ ok: true, count: PENDING_SPINS_COUNT });
});

app.post("/spins/consume", express.json(), (req, res) => {
  const want = Number(req.body?.count || 0);
  const taken = consumePendingSpins(want);
  res.json({ ok: true, taken });
});

/* ====== krótkoterminowa kolejka WS ====== */
const pendingSpins = [];
function isAnyWsConnected() {
  for (const c of wss.clients) if (c.readyState === 1) return true;
  return false;
}
function broadcastOrQueue(obj) {
  if (isAnyWsConnected()) broadcast(obj);
  else {
    if (obj?.action === "spin" && Number.isFinite(obj.times) && obj.times > 0) {
      pendingSpins.push(obj.times);
      const total = pendingSpins.reduce((a,b)=>a+b,0);
      console.log(`[WS] No clients. Queued spins: +${obj.times} (total in queue: ${total})`);
    } else {
      console.log("[WS] No clients. Dropping non-spin message.");
    }
  }
}

// RAW body before json()
app.post("/webhook", express.raw({ type: "*/*", limit: "2mb" }), async (req, res) => {
  const startedAt = Date.now();
  try {
    const msgId   = req.get("Kick-Event-Message-Id");
    const ts      = req.get("Kick-Event-Message-Timestamp");
    const sigB64  = req.get("Kick-Event-Signature");
    const eType   = req.get("Kick-Event-Type");

    console.log("[WEBHOOK] ⇢ Incoming");
    console.log("[WEBHOOK] Headers:", {
      "Kick-Event-Message-Id": msgId || null,
      "Kick-Event-Message-Timestamp": ts || null,
      "Kick-Event-Type": eType || null,
      "Kick-Event-Signature": sigB64 ? `(len=${sigB64.length})` : null,
      "Content-Type": req.get("content-type") || null,
      "User-Agent": req.get("user-agent") || null,
      ip: req.ip,
    });

    if (!msgId || !ts || !sigB64) {
      console.warn("[WEBHOOK] Missing required signature headers");
      return res.status(400).send("Missing signature headers");
    }
    if (SEEN_IDS.has(msgId)) {
      console.log("[WEBHOOK] Duplicate message id -> 200 ok-duplicate");
      return res.status(200).send("ok-duplicate");
    }

    const sentAt = Date.parse(ts);
    const MAX_SKEW_MS = 5 * 60 * 1000;
    if (!Number.isFinite(sentAt)) return res.status(400).send("Invalid timestamp");
    const skew = Math.abs(Date.now() - sentAt);
    console.log("[WEBHOOK] Timestamp skew(ms):", skew);
    if (skew > MAX_SKEW_MS) return res.status(400).send("Stale timestamp");

    const rawBody = Buffer.isBuffer(req.body) ? req.body : Buffer.from(req.body || "");
    const baseStr = `${msgId}.${ts}.${rawBody.toString("utf8")}`;
    console.log("[WEBHOOK] Body bytes:", rawBody.length, " | Signed string length:", baseStr.length);

    const verifier = crypto.createVerify("RSA-SHA256");
    verifier.update(baseStr, "utf8");
    verifier.end();
    const verified = verifier.verify(KICK_PUBLIC_KEY_PEM, sigB64, "base64");
    console.log("[WEBHOOK] Signature verified:", verified);
    if (!verified) return res.status(401).send("Invalid signature");

    rememberId(msgId);

    let payload = {};
    try { payload = JSON.parse(rawBody.toString("utf8")); }
    catch { return res.status(400).send("Invalid JSON"); }

    const type = eType || payload?.type || payload?.event || "unknown";
    console.log("[WEBHOOK] ✅ OK type:", type);

    // Challenge
    if (type === "webhook_callback_verification" && payload?.challenge) {
      console.log("[WEBHOOK] Responding with challenge");
      return res.json({ challenge: payload.challenge });
    }

    // Gifts -> spins
    if (type === "channel.subscription.gifts") {
      const { gifter = {}, giftees = [] } = payload || {};
      const count = Array.isArray(giftees) ? giftees.length : Number(payload?.count || 0);
      console.log("[WEBHOOK] 🎁 Gifts summary:", { gifter: gifter?.username || "Anon", count });
      const spins = Math.floor(count / 5) || (count >= 5 ? 1 : 0);
      if (spins > 0) {
        // 1) zawsze do licznika (bezstratnie)
        addPendingSpins(spins);
        // 2) realtime do WS (best-effort)
        console.log("[WEBHOOK] → Broadcasting spins:", spins);
        broadcastOrQueue({ action: "spin", times: spins });
      } else {
        console.log("[WEBHOOK] No spins (count < 5)");
      }
    } else {
      const short = JSON.stringify(payload).slice(0, 500);
      console.log("[WEBHOOK] Unhandled event:", type, "| payload:", short + (short.length === 500 ? "… (truncated)" : ""));
    }

    console.log(`[WEBHOOK] Done in ${Date.now() - startedAt}ms`);
    return res.status(200).send("ok");
  } catch (e) {
    console.error(`[WEBHOOK] Handler error:`, e);
    return res.status(400).send("Bad webhook");
  }
});

/* =======================================================================================
   CONFIG plik + GOALS + helpers
   ======================================================================================= */
function ensureDirFor(filePath) {
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}
function loadJsonSafe(file, fallback) {
  try {
    if (!fs.existsSync(file)) return fallback;
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch { return fallback; }
}

// Wheel config
function loadConfigItems() {
  const obj = loadJsonSafe(CFG_PATH, null);
  if (obj && Array.isArray(obj.items)) return obj.items;
  return null;
}
function normalizeItemsTo100(items) {
  const safe = (x) => Math.max(0, Number(x) || 0);
  const sum = items.reduce((s, it) => s + safe(it.weight), 0);
  if (sum <= 0) {
    const eq = items.length ? 100 / items.length : 0;
    return items.map(it => ({ ...it, weight: +eq.toFixed(2) }));
  }
  return items.map(it => ({ ...it, weight: +((safe(it.weight) * 100) / sum).toFixed(2) }));
}
function saveConfigItems(items) {
  ensureDirFor(CFG_PATH);
  const normalized = normalizeItemsTo100(items);
  fs.writeFileSync(CFG_PATH, JSON.stringify({ items: normalized }, null, 2));
  console.log(`[config] saved ${normalized.length} items (normalized to 100%) -> ${CFG_PATH}`);
  return normalized;
}

// Goals
function loadGoals() {
  const arr = loadJsonSafe(GOALS_PATH, []);
  return Array.isArray(arr) ? arr : [];
}
function saveGoals(arr) {
  ensureDirFor(GOALS_PATH);
  const list = Array.isArray(arr) ? arr.map(String) : [];
  fs.writeFileSync(GOALS_PATH, JSON.stringify(list, null, 2));
  console.log(`[goals] saved ${list.length} goals -> ${GOALS_PATH}`);
  return list;
}

// ===== HOME (dashboard) =====
app.get("/home", (req, res) => {
  const file = path.join(PUB, "home.html");
  if (!fs.existsSync(file)) return res.status(404).send("home.html not found");
  res.sendFile(file);
});

// Status: token, broadcaster_id, subskrypcje
let CACHED_BROADCASTER_ID = null;
async function getBroadcasterId() {
  if (CACHED_BROADCASTER_ID) return CACHED_BROADCASTER_ID;
  const token = await ensureAccessToken();
  const r = await fetch("https://api.kick.com/public/v1/users", {
    headers: { Authorization: `Bearer ${token}` }
  });
  if (!r.ok) throw new Error(`users (self) failed: ${r.status} ${await r.text().catch(()=> "")}`);
  const data = await r.json();
  const id = data?.data?.[0]?.user_id;
  if (!Number.isFinite(Number(id))) throw new Error("Cannot determine broadcaster_user_id from /public/v1/users");
  CACHED_BROADCASTER_ID = Number(id);
  return CACHED_BROADCASTER_ID;
}

app.get("/status", async (req, res) => {
  try {
    const tokens = loadTokens();
    const hasTokens = !!tokens?.access_token;
    let broadcasterId = null;
    let scope = tokens?.scope || null;
    let subs = [];

    if (hasTokens) {
      const token = await ensureAccessToken();
      broadcasterId = await getBroadcasterId();
      const r = await fetch(`https://api.kick.com/public/v1/events/subscriptions?broadcaster_user_id=${broadcasterId}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (r.ok) {
        const j = await r.json().catch(()=> ({}));
        subs = Array.isArray(j?.data) ? j.data : [];
      }
    }

    res.json({
      ok: true,
      hasTokens,
      scope,
      broadcaster_user_id: broadcasterId,
      subscriptions: subs
    });
  } catch (e) {
    console.error("[/status] error:", e);
    res.status(500).json({ ok: false, error: e.message });
  }
});

// Ręczna subskrypcja (webhook) z panelu
app.post("/subscribe", express.json(), async (req, res) => {
  try {
    const token = await ensureAccessToken();
    const broadcasterId = await getBroadcasterId();
    const base = getBaseUrl(req);
    const cb = `${base}/webhook`;

    const response = await fetch("https://api.kick.com/public/v1/events/subscriptions", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        broadcaster_user_id: Number(broadcasterId),
        events: [{ name: "channel.subscription.gifts", version: 1 }],
        method: "webhook",
        callback: cb
      })
    });
    const text = await response.text();
    console.log("[SUBSCRIBE][/home] status:", response.status, text);
    if (!response.ok) throw new Error(`Failed to subscribe: ${response.status} ${text}`);

    res.json({ ok: true, data: JSON.parse(text) });
  } catch (e) {
    console.error("[/subscribe] error:", e);
    res.status(400).json({ ok: false, error: e.message });
  }
});

// === Goals endpoints ===
app.get("/goals", (req, res) => {
  try {
    const goals = loadGoals();
    res.json({ ok: true, goals });
  } catch {
    res.json({ ok: true, goals: [] });
  }
});
app.post("/goals", express.json(), (req, res) => {
  if (!ADMIN_KEY || req.get("X-Admin-Key") !== ADMIN_KEY) {
    return res.status(401).json({ ok: false, error: "Unauthorized" });
  }
  try {
    const goals = Array.isArray(req.body?.goals) ? req.body.goals : [];
    const saved = saveGoals(goals);
    res.json({ ok: true, goals: saved });
  } catch (e) {
    res.status(500).json({ ok: false, error: "Save failed" });
  }
});

// === Wheel config endpoints ===
app.get("/config", (_req, res) => {
  res.json({ ok: true, items: loadConfigItems() });
});

app.post("/config", express.json(), (req, res) => {
  if (!ADMIN_KEY || req.get("X-Admin-Key") !== ADMIN_KEY) {
    return res.status(401).json({ ok: false, error: "Unauthorized" });
  }
  let items = Array.isArray(req.body?.items) ? req.body.items : null;
  if (!items) return res.status(400).json({ ok: false, error: "Missing items[]" });

  const normalized = saveConfigItems(items);
  broadcast({ type: "config", items: normalized });
  res.json({ ok: true, items: normalized });
});

// ===== Reszta middleware =====
app.use(bodyParser.json());
app.use(express.static(PUB));

// Ogłoszenie na czat po spinie (non-blocking)
async function postChatMessage(content) {
  if (!content?.trim()) return;
  try {
    const token = await ensureAccessToken();
    const broadcasterId = await getBroadcasterId();
    const r = await fetch("https://api.kick.com/public/v1/chat", {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ broadcaster_user_id: broadcasterId, content: content.slice(0,500), type: "user" })
    });
    if (!r.ok) console.warn(`chat send failed: ${r.status} ${await r.text().catch(()=> "")}`);
  } catch (e) { console.warn("[chat] error:", e.message); }
}

app.post("/chat/announce", async (req, res) => {
  try {
    const label = String(req.body?.label ?? "").trim();
    if (!label) return res.status(400).json({ ok:false, error:"Missing label" });
    const msg = `🎯 Koło fortuny: ${label}`;
    await postChatMessage(msg);
    res.json({ ok:true });
  } catch (e) {
    console.error("chat/announce error:", e);
    res.status(200).json({ ok:false, warn: e.message });
  }
});

// Index / Health
app.get("/", (req, res) => {
  const file = path.join(PUB, "index.html");
  if (!fs.existsSync(file)) return res.status(404).send("index.html not found");
  res.sendFile(file);
});
app.get("/health", (_, res) => res.send("OK"));

/* =======================================================================================
   OAuth: login/callback (dynamiczne redirectUri)
   ======================================================================================= */
const oauthStore = new Map();

app.get("/auth/login", async (req, res) => {
  try {
    const desiredScopes = [
      "user:read", "channel:read", "channel:write",
      "chat:write", "events:subscribe",
    ];
    const redirectUri = process.env.KICK_REDIRECT_URI || `${getBaseUrl(req)}/auth/callback`;
    const authClient = new KickAuthClient({
      clientId:     process.env.KICK_CLIENT_ID     || "YOUR_CLIENT_ID",
      clientSecret: process.env.KICK_CLIENT_SECRET || "YOUR_CLIENT_SECRET",
      redirectUri,
    });

    let { url, state, codeVerifier } = await authClient.getAuthorizationUrl({ scopes: desiredScopes });
    oauthStore.set(state, { codeVerifier, redirectUri });

    const scopeParam = encodeURIComponent(desiredScopes.join(" "));
    if (url.includes("scope=")) url = url.replace(/([?&])scope=[^&]*/i, `$1scope=${scopeParam}`);
    else url += (url.includes("?") ? "&" : "?") + `scope=${scopeParam}`;
    if (!/([?&])prompt=/.test(url)) url += "&prompt=consent";

    console.log("[AUTH URL]", url);
    res.redirect(url);
  } catch (e) {
    console.error("Auth init error:", e);
    res.status(500).send("Failed to start auth");
  }
});

app.get("/auth/callback", async (req, res) => {
  try {
    const { code, state } = req.query;
    if (!code || !state) return res.status(400).send("Missing code/state");

    const stored = oauthStore.get(state);
    if (!stored?.codeVerifier || !stored?.redirectUri) return res.status(400).send("Invalid state");
    oauthStore.delete(state);

    const authClient = new KickAuthClient({
      clientId:     process.env.KICK_CLIENT_ID     || "YOUR_CLIENT_ID",
      clientSecret: process.env.KICK_CLIENT_SECRET || "YOUR_CLIENT_SECRET",
      redirectUri:  stored.redirectUri,
    });

    const tokens = await authClient.getAccessToken(String(code), stored.codeVerifier);
    const saved = withExpiresAt(tokens);
    saveTokens(saved);

    console.log("OAuth tokens:", {
      access_token: mask(saved.access_token),
      refresh_token: mask(saved.refresh_token),
      expires_in: saved.expires_in,
      expires_at: saved.expires_at,
      scope: saved.scope,
    });
    res.send("Auth OK. You can close this window.");
  } catch (e) {
    console.error("Auth error:", e);
    res.status(500).send("Auth failed");
  }
});

/* =======================================================================================
   SUBSKRYPCJE EVENTÓW – /setup + watchdog
   ======================================================================================= */
async function subscribeToEvents(token, broadcasterId, callbackUrl) {
  const response = await fetch("https://api.kick.com/public/v1/events/subscriptions", {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${token}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      broadcaster_user_id: Number(broadcasterId),
      events: [
        { name: "channel.subscription.gifts", version: 1 }
      ],
      method: "webhook",
      callback: callbackUrl
    })
  });

  const text = await response.text();
  console.log("[SUBSCRIBE] status:", response.status, text);
  if (!response.ok) throw new Error(`Failed to subscribe: ${response.status} ${text}`);
  return JSON.parse(text);
}

async function listSubscriptions(token, broadcasterId) {
  const r = await fetch(`https://api.kick.com/public/v1/events/subscriptions?broadcaster_user_id=${broadcasterId}`, {
    headers: { Authorization: `Bearer ${token}` }
  });
  if (!r.ok) return [];
  const j = await r.json().catch(()=> ({}));
  return Array.isArray(j?.data) ? j.data : [];
}

// Utrzymujemy ostatnio znany callback do watchdoga
let LAST_CALLBACK_URL = null;

app.get("/setup", async (req, res) => {
  const hasTokens = !!loadTokens()?.access_token;
  const base = getBaseUrl(req);
  LAST_CALLBACK_URL = `${base}/webhook`; // zapamiętaj dla watchdoga
  let subLine = '<span class="warn">pomińnięto (brak tokenu)</span>';

  if (hasTokens) {
    try {
      const token = await ensureAccessToken();
      const broadcasterId = await getBroadcasterId();
      const cb = LAST_CALLBACK_URL;

      console.log("[SUBSCRIBE] Trying to subscribe:", {
        broadcaster_user_id: String(broadcasterId),
        events: [{ name: "channel.subscription.gifts", version: 1 }],
        method: "webhook",
        callback: cb
      });

      const resp = await subscribeToEvents(token, broadcasterId, cb);
      subLine = '<span class="ok">ok</span>';
      console.log("[SUBSCRIBE] success:", resp);
    } catch (e) {
      console.warn("[SUBSCRIBE] failed:", e?.message);
      subLine = `<span class="warn">błąd: ${String(e?.message || e)}</span>`;
    }
  }

  res.type("html").send(`
    <!doctype html>
    <html><head><meta charset="utf-8"><title>Kick Wheel – Setup</title>
    <style>
      body { font-family: system-ui; margin: 40px; }
      .ok { color: #16a34a; }
      .warn { color: #b45309; }
      a.btn { display:inline-block; padding:10px 14px; border:1px solid #333; border-radius:8px; text-decoration:none; margin-top:6px; }
      code { background:#f6f8fa; padding:2px 6px; border-radius:6px; }
    </style>
    </head><body>
      <h1>Kick Wheel – konfiguracja</h1>
      <p>Status tokenów: ${hasTokens ? '<b class="ok">OK (zapisane)</b>' : '<b class="warn">brak – zaloguj</b>'}</p>
      <p><a class="btn" href="/auth/login">🔑 Zaloguj z Kick</a></p>
      <p>Subskrypcja eventów: ${subLine}</p>
      <hr>
      <h2>OBS</h2>
      <ol>
        <li>W OBS dodaj <b>Browser Source</b> z URL: <code>${base}/?overlay=1</code></li>
        <li>Tło strony jest przezroczyste.</li>
        <li>Webhook callback: <code>${base}/webhook</code></li>
      </ol>
      <p>Panel: <a class="btn" href="/home">🏠 /home</a></p>
      <p>Test koła: <a class="btn" href="/test/1">▶️ /test/1</a></p>
    </body></html>
  `);
});

/* Watchdog subskrypcji – co 10 min upewnia się, że mamy event gifts */
async function ensureSubscribed() {
  try {
    if (!LAST_CALLBACK_URL) return; // jeszcze nie wiemy jaki jest publiczny callback — odwiedź /setup
    const token = await ensureAccessToken();
    const broadcasterId = await getBroadcasterId();
    const subs = await listSubscriptions(token, broadcasterId);
    const hasGifts = subs.some(s => s?.name === "channel.subscription.gifts");
    if (!hasGifts) {
      console.log("[SUBSCRIBE][watchdog] missing gifts sub -> creating");
      await subscribeToEvents(token, broadcasterId, LAST_CALLBACK_URL);
    } else {
      console.log("[SUBSCRIBE][watchdog] OK (gifts sub exists)");
    }
  } catch (e) {
    console.warn("[SUBSCRIBE][watchdog] error:", e?.message || e);
  }
}
setInterval(ensureSubscribed, 10 * 60 * 1000);

/* Watchdog tokenów – co 2 min, jeśli do końca < 15 min, odśwież */
async function refreshIfSoon() {
  try {
    const t = loadTokens();
    if (!t?.refresh_token) return;
    const left = secondsUntilExpiry(t);
    if (!Number.isFinite(left) || left <= 15 * 60) {
      console.log(`[tokens] watchdog refresh (left ${left}s)`);
      const refreshed = await refreshAccessTokenManual(t.refresh_token);
      const merged = withExpiresAt({ ...t, ...refreshed });
      saveTokens(merged);
    }
  } catch (e) {
    console.warn("[tokens] watchdog error:", e?.message || e);
  }
}
setInterval(refreshIfSoon, 120_000);

/* =======================================================================================
   DEBUG / TESTY
   ======================================================================================= */
app.get("/test/:n", (req, res) => {
  const n = parseInt(req.params.n, 10) || 0;
  broadcastOrQueue({ action: "spin", times: n });
  res.send(`sent ${n}`);
});

app.get("/debug/oauth/ping", async (_req, res) => {
  try {
    const token = await ensureAccessToken();
    const r = await fetch("https://api.kick.com/public/v1/users", {
      headers: { Authorization: `Bearer ${token}` }
    });
    const text = await r.text();
    res.status(r.status).type("application/json; charset=utf-8").send(text);
  } catch (e) {
    console.error("OAuth ping error:", e);
    res.status(500).send("OAuth ping failed: " + e.message);
  }
});

app.post("/debug/oauth/refresh", async (_req, res) => {
  try {
    const tokens = loadTokens();
    if (!tokens?.refresh_token) return res.status(400).json({ ok: false, error: "No refresh_token stored" });
    const refreshed = await refreshAccessTokenManual(tokens.refresh_token);
    const merged = withExpiresAt({ ...tokens, ...refreshed });
    saveTokens(merged);
    res.json({ ok: true, access_token: mask(merged.access_token), refresh_token: mask(merged.refresh_token), expires_at: merged.expires_at });
  } catch (e) {
    console.error("Manual refresh error:", e);
    res.status(500).json({ ok: false, error: e.message });
  }
});

app.get("/debug/token", (_req, res) => {
  const t = loadTokens();
  if (!t) return res.json({ ok: true, tokens: null });
  res.json({ ok: true, tokens: { access_token: mask(t.access_token), refresh_token: mask(t.refresh_token), expires_in: t.expires_in, expires_at: t.expires_at, scope: t.scope }});
});

/* =======================================================================================
   HTTP + WS (z heartbeat i opróżnianiem kolejki)
   ======================================================================================= */
const server = http.createServer(app);
const wss = new WebSocketServer({ noServer: true });

server.on("upgrade", (req, socket, head) => {
  if (req.url !== "/ws") { socket.destroy(); return; }
  wss.handleUpgrade(req, socket, head, (ws) => { wss.emit("connection", ws, req); });
});

wss.on("connection", (ws, req) => {
  console.log("WS client connected:", req.socket.remoteAddress);

  // heartbeat
  ws.isAlive = true;
  ws.on("pong", () => { ws.isAlive = true; });

  // po połączeniu wyślij zaległe spiny z kolejki WS
  const totalQueued = pendingSpins.reduce((a,b)=>a+b,0);
  if (totalQueued > 0) {
    const n = pendingSpins.splice(0).reduce((a,b)=>a+b,0);
    console.log(`[WS] Flushing queued spins -> ${n}`);
    broadcast({ action: "spin", times: n });
  }

  // ZAWSZE poinformuj klienta o stanie licznika bezstratnego
  try { ws.send(JSON.stringify({ action: "pending", count: PENDING_SPINS_COUNT })); } catch {}

  ws.on("close", () => console.log("WS closed"));
  ws.on("error", (e) => console.error("WS client error:", e));
});
wss.on("error", (err) => console.error("WS server error:", err));

// ping co 30s
setInterval(() => {
  for (const ws of wss.clients) {
    if (ws.isAlive === false) {
      console.log("[WS] terminating dead connection");
      ws.terminate();
      continue;
    }
    ws.isAlive = false;
    try { ws.ping(); } catch {}
  }
}, 30_000);

function broadcast(obj) {
  const msg = JSON.stringify(obj);
  for (const client of wss.clients) if (client.readyState === 1) client.send(msg);
}

server.listen(PORT_HTTP, () => {
  console.log(`HTTP on http://localhost:${PORT_HTTP}`);
  console.log(`WS on    ws://localhost:${PORT_HTTP}/ws`);
  console.log("Public:", PUB, fs.existsSync(PUB) ? "(ok)" : "(missing)");
  console.log("[ENV]", {
    KICK_CLIENT_ID: process.env.KICK_CLIENT_ID,
    KICK_REDIRECT_URI: process.env.KICK_REDIRECT_URI || "<dynamic>",
    WEBHOOK_SECRET: mask(WEBHOOK_SECRET),
    TOK_PATH, CFG_PATH, GOALS_PATH,
    ADMIN_KEY: ADMIN_KEY ? "(set)" : "(missing)"
  });
});
