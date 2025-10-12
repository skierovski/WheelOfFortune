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

// ---- Config / env ----
const PORT_HTTP = Number(process.env.PORT) || 3000;
const PUB = path.join(__dirname, "public");
const WEBHOOK_SECRET = process.env.KICK_WEBHOOK_SECRET || process.env.WEBHOOK_SECRET || "dev_webhook_secret";

// Lżejszy CSP żeby WS mógł się łączyć z lokalnymi/remote hostami
app.use((req, res, next) => {
  res.setHeader(
    "Content-Security-Policy",
    [
      "default-src 'self' data: blob:",
      `connect-src 'self' http://localhost:${PORT_HTTP} ws://localhost:${PORT_HTTP} https: wss:`,
      `script-src 'self' 'unsafe-inline' 'unsafe-eval' http://localhost:${PORT_HTTP}`,
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: blob:",
      "font-src 'self' data:"
    ].join("; ")
  );
  next();
});

/* =======================================================================================
   TOKEN STORE + AUTO REFRESH
   - zapis do tokens.json
   - auto-odświeżanie przy użyciu KickAuthClient.refreshAccessToken (jeśli jest)
   ======================================================================================= */

const TOK_PATH = process.env.TOK_PATH || path.join(process.cwd(), "tokens.json");

function mask(v) {
  if (!v || typeof v !== 'string') return v;
  if (v.length <= 8) return v;
  return v.slice(0, 4) + "..." + v.slice(-4);
}

function loadTokens() {
  try {
    const raw = fs.readFileSync(TOK_PATH, "utf8");
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function saveTokens(t) {
  try {
    fs.writeFileSync(TOK_PATH, JSON.stringify(t, null, 2));
    console.log("[tokens] saved:", {
      access_token: mask(t.access_token),
      refresh_token: mask(t.refresh_token),
      expires_at: t.expires_at
    });
  } catch (e) {
    console.error("[tokens] save failed:", e);
  }
}

function withExpiresAt(tokens) {
  // jeśli brak expires_at – wylicz z expires_in
  if (!tokens) return null;
  const skewMs = 60_000 * 5; // 5 minut bufora
  const now = Date.now();
  if (!tokens.expires_at && Number.isFinite(tokens.expires_in)) {
    tokens.expires_at = now + (Number(tokens.expires_in) * 1000) - skewMs;
  }
  return tokens;
}

const kickAuth = new KickAuthClient({
  clientId:     process.env.KICK_CLIENT_ID     || "YOUR_CLIENT_ID",
  clientSecret: process.env.KICK_CLIENT_SECRET || "YOUR_CLIENT_SECRET",
  redirectUri:  process.env.KICK_REDIRECT_URI  || `http://localhost:${PORT_HTTP}/auth/callback`,
});

// Zapewnia ważny access_token (autorefresh jeśli wygasł lub za chwilę wygaśnie)
async function ensureAccessToken() {
  let tokens = withExpiresAt(loadTokens());
  if (!tokens?.access_token) throw new Error("No tokens stored. Log in via /auth/login");

  const now = Date.now();
  const needRefresh = !tokens.expires_at || now >= tokens.expires_at;

  if (!needRefresh) return tokens.access_token;

  // Spróbuj użyć metody klienta jeśli istnieje
  if (typeof kickAuth.refreshAccessToken === "function") {
    console.log("[tokens] refreshing via KickAuthClient.refreshAccessToken()");
    const refreshed = await kickAuth.refreshAccessToken(tokens.refresh_token);
    const merged = withExpiresAt({
      ...tokens,
      ...refreshed,
      // niektóre biblioteki zwracają nowe expires_in, token_type, scope
    });
    saveTokens(merged);
    return merged.access_token;
  }

  // Fallback: jeśli biblioteka nie ma metody, rzuć błąd / zrób własny fetch do endpointu token
  // (Możemy dorobić gdyby było trzeba)
  throw new Error("refreshAccessToken() not available on KickAuthClient");
}

/* =======================================================================================
   WEBHOOK z walidacją HMAC (Kick-Signature: hex sha256)
   - UWAGA: surowe body MUSI być przed bodyParser.json()
   ======================================================================================= */
app.post("/webhook", express.raw({ type: "*/*" }), async (req, res) => {
  try {
    // 1) Walidacja HMAC
    const signature = req.get("Kick-Signature");
    if (!signature) return res.status(401).send("Missing signature");

    const hmac = crypto.createHmac("sha256", WEBHOOK_SECRET).update(req.body).digest("hex");
    const sigBuf = Buffer.from(signature, "hex");
    const hmacBuf = Buffer.from(hmac, "hex");
    if (
      sigBuf.length !== hmacBuf.length ||
      !crypto.timingSafeEqual(sigBuf, hmacBuf)
    ) {
      return res.status(401).send("Invalid signature");
    }

    // 2) JSON po walidacji
    let payload = {};
    try {
      payload = JSON.parse(req.body.toString("utf8"));
    } catch (e) {
      console.error("Webhook JSON parse error:", e);
      return res.status(400).send("Invalid JSON");
    }

    const eventType = req.get("Kick-Event-Type") || payload?.type || payload?.event;
    console.log("Webhook event:", eventType);

    if (eventType === "channel.subscription.gifts") {
      const { gifter = {}, giftees = [] } = payload || {};
      const count = Array.isArray(giftees) ? giftees.length : Number(payload?.count || 0);
      console.log(`🎁 ${gifter.username || "Anon"} gifted ${count} subs`);

      const spins = Math.floor(count / 5) || (count >= 5 ? 1 : 0);
      if (spins > 0) {
        broadcast({ action: "spin", times: spins });
      }
    }

    res.status(200).send("ok");
  } catch (e) {
    console.error("Webhook error:", e);
    return res.status(400).send("Bad webhook");
  }
});

// ===== Reszta middleware =====
app.use(bodyParser.json());
app.use(express.static(PUB));

// Po każdej wygranej front woła nas i my wysyłamy wiadomość na czat.
app.post("/chat/announce", async (req, res) => {
  try {
    const label = String(req.body?.label ?? "").trim();
    if (!label) return res.status(400).json({ ok:false, error:"Missing label" });

    // Tu sformatuj własny tekst:
    const msg = `🎯 Koło fortuny: ${label}`;
    await postChatMessage(msg);

    res.json({ ok:true });
  } catch (e) {
    console.error("chat/announce error:", e);
    res.status(500).json({ ok:false, error: e.message });
  }
});


// Index
app.get("/", (req, res) => {
  const file = path.join(PUB, "index.html");
  if (!fs.existsSync(file)) return res.status(404).send("index.html not found");
  res.sendFile(file);
});

// Health
app.get("/health", (_, res) => res.send("OK"));

/* =======================================================================================
   OAuth: login/callback (+ zapis tokenów)
   ======================================================================================= */
const oauthStore = new Map();

app.get("/auth/login", async (_req, res) => {
  try {
    const desiredScopes = [
      "user:read",
      "channel:read",
      "channel:write",
      "chat:write",
      "events:read",
      "events:write",
    ];

    const { url, state, codeVerifier } = await kickAuth.getAuthorizationUrl({
      scopes: desiredScopes,
    });
    oauthStore.set(state, codeVerifier);

    // Wymuś prompt=consent i scope dokładnie jak chcemy (space-separated)
    const scopeParam = encodeURIComponent(desiredScopes.join(" "));
    let authUrl = url;

    if (authUrl.includes("scope=")) {
      authUrl = authUrl.replace(/([?&])scope=[^&]*/i, `$1scope=${scopeParam}`);
    } else {
      authUrl += (authUrl.includes("?") ? "&" : "?") + `scope=${scopeParam}`;
    }
    if (!/([?&])prompt=/.test(authUrl)) {
      authUrl += "&prompt=consent";
    }

    console.log("[AUTH URL]", authUrl); // <-- sprawdzimy co naprawdę leci
    res.redirect(authUrl);
  } catch (e) {
    console.error("Auth init error:", e);
    res.status(500).send("Failed to start auth");
  }
});


app.get("/auth/callback", async (req, res) => {
  try {
    const { code, state } = req.query;
    if (!code || !state) return res.status(400).send("Missing code/state");
    const codeVerifier = oauthStore.get(state);
    if (!codeVerifier) return res.status(400).send("Invalid state");

    const tokens = await kickAuth.getAccessToken(String(code), codeVerifier);
    oauthStore.delete(state);

    const stored = withExpiresAt(tokens);
    saveTokens(stored);

    console.log("OAuth tokens:", {
      access_token: mask(stored.access_token),
      refresh_token: mask(stored.refresh_token),
      expires_in: stored.expires_in,
      expires_at: stored.expires_at
    });
    res.send("Auth OK. You can close this window.");
  } catch (e) {
    console.error("Auth error:", e);
    res.status(500).send("Auth failed");
  }
});

/* =======================================================================================
   DEBUG / NARZĘDZIA
   ======================================================================================= */

// Prosty test WS: /test/3 -> 3 spiny
app.get("/test/:n", (req, res) => {
  const n = parseInt(req.params.n, 10) || 0;
  broadcast({ action: "spin", times: n });
  res.send(`sent ${n}`);
});


// ===== Kick Chat helpers =====

// cache na broadcaster_user_id (id zalogowanego użytkownika, którego token mamy)
let CACHED_BROADCASTER_ID = null;

async function getBroadcasterId() {
  if (CACHED_BROADCASTER_ID) return CACHED_BROADCASTER_ID;

  const token = await ensureAccessToken();

  // POPRAWNY endpoint wg docs: GET /public/v1/users
  const r = await fetch("https://api.kick.com/public/v1/users", {
    headers: { Authorization: `Bearer ${token}` }
  });

  if (!r.ok) {
    const t = await r.text().catch(() => "");
    throw new Error(`users (self) failed: ${r.status} ${t}`);
  }

  const data = await r.json();
  // struktura wg docs: { data: [ { user_id, name, email, ... } ], message }
  const id = data?.data?.[0]?.user_id;
  if (!Number.isFinite(Number(id))) {
    throw new Error("Cannot determine broadcaster_user_id from /public/v1/users");
  }

  CACHED_BROADCASTER_ID = Number(id);
  return CACHED_BROADCASTER_ID;
}

/**
 * Wyślij wiadomość na czat Kick (typ 'user' używając tokenu streamera).
 * Wymagane scope: chat:write
 * Docs: https://docs.kick.com/apis/chat (POST /public/v1/chat)
 */
async function postChatMessage(content) {
  if (!content || !content.trim()) return;

  const token = await ensureAccessToken();
  const broadcasterId = await getBroadcasterId();

  const payload = {
    broadcaster_user_id: broadcasterId,
    content: content.slice(0, 500),
    type: "user"
  };

  const r = await fetch("https://api.kick.com/public/v1/chat", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify(payload)
  });

  if (!r.ok) {
    const txt = await r.text().catch(() => "");
    throw new Error(`chat send failed: ${r.status} ${txt}`);
  }
  return r.json();
}

//SETUP

app.get("/setup", (_req, res) => {
  const hasTokens = !!loadTokens()?.access_token;
  res.type("html").send(`
    <!doctype html>
    <html><head><meta charset="utf-8"><title>Kick Wheel – Setup</title>
    <style>body{font-family:system-ui;margin:40px} .ok{color:#16a34a} .warn{color:#b45309} a.btn{display:inline-block;padding:10px 14px;border:1px solid #333;border-radius:8px;text-decoration:none}</style>
    </head><body>
      <h1>Kick Wheel – konfiguracja</h1>
      <p>Status tokenów: ${hasTokens ? '<b class="ok">OK (zapisane)</b>' : '<b class="warn">brak – zaloguj</b>'}</p>
      <p><a class="btn" href="/auth/login">🔑 Zaloguj z Kick</a></p>
      <hr>
      <h2>OBS</h2>
      <ol>
        <li>W OBS dodaj <b>Browser Source</b> z URL: <code>http://localhost:${PORT_HTTP}/?overlay=1</code></li>
        <li>Ustaw szer./wys. według canvasu (np. 1920×1080). Tło strony jest przezroczyste.</li>
      </ol>
      <p>Test koła: <a class="btn" href="/test/1">▶️ /test/1</a></p>
    </body></html>
  `);
});

// Ping do API z aktualnym tokenem (auto-refresh)
app.get("/debug/oauth/ping", async (req, res) => {
  try {
    const tokenFromQuery = req.query.token ? String(req.query.token) : null;
    const token = tokenFromQuery || (await ensureAccessToken());

    const r = await fetch("https://api.kick.com/v1/users/me", {
      headers: { Authorization: `Bearer ${token}` }
    });

    const text = await r.text();
    res.status(r.status).type("application/json; charset=utf-8").send(text);
  } catch (e) {
    console.error("OAuth ping error:", e);
    res.status(500).send("OAuth ping failed: " + e.message);
  }
});

// Wymuś odświeżenie „na żądanie”
app.post("/debug/oauth/refresh", async (_req, res) => {
  try {
    const tokens = loadTokens();
    if (!tokens?.refresh_token) {
      return res.status(400).json({ ok: false, error: "No refresh_token stored" });
    }
    if (typeof kickAuth.refreshAccessToken !== "function") {
      return res.status(400).json({ ok: false, error: "refreshAccessToken() not available" });
    }
    const refreshed = await kickAuth.refreshAccessToken(tokens.refresh_token);
    const merged = withExpiresAt({ ...tokens, ...refreshed });
    saveTokens(merged);
    res.json({
      ok: true,
      access_token: mask(merged.access_token),
      refresh_token: mask(merged.refresh_token),
      expires_at: merged.expires_at
    });
  } catch (e) {
    console.error("Manual refresh error:", e);
    res.status(500).json({ ok: false, error: e.message });
  }
});

// Podgląd statusu tokenów (zamaskowany)
app.get("/debug/token", (_req, res) => {
  const t = loadTokens();
  if (!t) return res.json({ ok: true, tokens: null });
  res.json({
    ok: true,
    tokens: {
      access_token: mask(t.access_token),
      refresh_token: mask(t.refresh_token),
      expires_in: t.expires_in,
      expires_at: t.expires_at
    }
  });
});

/* =======================================================================================
   HTTP + WS na tym samym porcie i ścieżce /ws
   ======================================================================================= */
const server = http.createServer(app);
const wss = new WebSocketServer({ noServer: true });

server.on("upgrade", (req, socket, head) => {
  if (req.url !== "/ws") {
    socket.destroy();
    return;
  }
  wss.handleUpgrade(req, socket, head, (ws) => {
    wss.emit("connection", ws, req);
  });
});

wss.on("connection", (ws, req) => {
  console.log("WS client connected:", req.socket.remoteAddress);
  ws.on("close", () => console.log("WS closed"));
  ws.on("error", (e) => console.error("WS client error:", e));
});

wss.on("error", (err) => console.error("WS server error:", err));

const broadcast = (obj) => {
  const msg = JSON.stringify(obj);
  for (const client of wss.clients) {
    if (client.readyState === 1) client.send(msg);
  }
};

server.listen(PORT_HTTP, () => {
  console.log(`HTTP on http://localhost:${PORT_HTTP}`);
  console.log(`WS on    ws://localhost:${PORT_HTTP}/ws`);
  console.log("Public:", PUB, fs.existsSync(PUB) ? "(ok)" : "(missing)");
  console.log("[ENV]", {
    KICK_CLIENT_ID: process.env.KICK_CLIENT_ID,
    KICK_REDIRECT_URI: process.env.KICK_REDIRECT_URI || `http://localhost:${PORT_HTTP}/auth/callback`,
    WEBHOOK_SECRET: mask(WEBHOOK_SECRET)
  });
});
