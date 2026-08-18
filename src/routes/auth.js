import { Router } from "express";
import { env } from "../utils/env.js";
import { setSessionCookie } from "../utils/cookies.js";
import { KickAuthClient } from "kick-auth";
import { fetchUserInfo } from "../services/kick.js";
import { saveTokens, tokenStore } from "../services/tokens.js";
import { getDb } from "../db.js";
import { encrypt } from "../utils/crypto.js";
import { parseCookies } from "../utils/cookies.js";
import { safeReturnPath } from "../utils/redirects.js";
import { consumeOAuthTransaction, storeOAuthTransaction } from "../services/oauthTransactions.js";
import { createSession, revokeCurrentSession } from "../services/sessions.js";
import { requireSession } from "../middleware/requireSession.js";

function isDevBypassAllowed(req) {
  if (env.NODE_ENV === "production") return false;
  if (!env.DEV_BYPASS_AUTH) return false;
  if (env.DEV_BYPASS_IPS.length) {
    const ip = (req.ip || "").replace("::ffff:", "");
    if (!env.DEV_BYPASS_IPS.includes(ip)) return false;
  }
  return true;
}

const router = Router();
const OAUTH_BINDING_COOKIE = "wheel_oauth";

function setOAuthBindingCookie(res, value, maxAge = 600) {
  const parts = [
    `${OAUTH_BINDING_COOKIE}=${encodeURIComponent(value)}`,
    "Path=/auth/callback",
    "HttpOnly",
    "SameSite=Lax",
    `Max-Age=${maxAge}`,
  ];
  if (env.NODE_ENV === "production") parts.push("Secure");
  res.append("Set-Cookie", parts.join("; "));
}

function getBaseUrl(req) {
  const proto = (req.headers["x-forwarded-proto"] || req.protocol || "http").split(",")[0].trim();
  const host = (req.headers["x-forwarded-host"] || req.get("host")).split(",")[0].trim();
  return `${proto}://${host}`;
}

router.get("/auth/login", async (req, res) => {
  try {
    // Dev bypass
    if (isDevBypassAllowed(req)) {
      const fake = Number.isFinite(env.DEV_FAKE_BID) ? env.DEV_FAKE_BID : 999999;
      // Ensure dev streamer exists
      let streamer = getDb().getStreamerById(fake);
      if (!streamer) {
        streamer = getDb().upsertStreamer({
          broadcaster_id: fake,
          kick_username: "dev_user",
          display_name: "Dev User",
          access_token: null,
          refresh_token: null,
        });
      }
      createSession(req, res, fake);
      const ret = safeReturnPath(req.query.ret);
      console.warn(`[AUTH][DEV] Skip OAuth -> fake session ${fake}, redirect ${ret}`);
      return res.redirect(ret);
    }

    const retTarget = safeReturnPath(req.query.ret);

    const desiredScopes = ["user:read"];
    const redirectUri = env.KICK_REDIRECT_URI || `${getBaseUrl(req)}/auth/callback`;
    const authClient = new KickAuthClient({
      clientId: env.KICK_CLIENT_ID,
      clientSecret: env.KICK_CLIENT_SECRET,
      redirectUri,
    });

    let { url, state, codeVerifier } = await authClient.getAuthorizationUrl({ scopes: desiredScopes });
    const scopeParam = encodeURIComponent(desiredScopes.join(" "));
    if (url.includes("scope=")) url = url.replace(/([?&])scope=[^&]*/i, `$1scope=${scopeParam}`);
    else url += (url.includes("?") ? "&" : "?") + `scope=${scopeParam}`;
    if (!/([?&])prompt=/.test(url)) url += "&prompt=consent";
    const ret = safeReturnPath(req.query.ret);
    const tx = storeOAuthTransaction({ state, codeVerifier, redirectUri, returnPath: ret });
    setOAuthBindingCookie(res, tx.browserBinding);

    res.redirect(url);
  } catch (e) {
    console.error("Auth init error:", e);
    res.status(500).send("Failed to start auth");
  }
});

router.get("/auth/callback", async (req, res) => {
  try {
    const { code, state } = req.query;
    if (!code || !state) return res.status(400).send("Missing code/state");

    const binding = parseCookies(req)[OAUTH_BINDING_COOKIE];
    const stored = consumeOAuthTransaction(String(state), binding);
    setOAuthBindingCookie(res, "", 0);
    if (!stored?.codeVerifier || !stored?.redirectUri) return res.status(400).send("Invalid or expired state");

    const authClient = new KickAuthClient({
      clientId: env.KICK_CLIENT_ID,
      clientSecret: env.KICK_CLIENT_SECRET,
      redirectUri: stored.redirectUri,
    });

    const tokens = await authClient.getAccessToken(String(code), stored.codeVerifier);
    const withExpiry = tokenStore.withExpiresAt(tokens);

    // Fetch user info from Kick using the fresh access token
    const userInfo = await fetchUserInfo(withExpiry.access_token);
    const bid = userInfo.user_id;

    // Check if this is a new streamer vs returning streamer
    const existing = getDb().getStreamerById(bid);
    const moderatorships = getDb().getModeratorships(bid);
    const isModOnly = !existing && moderatorships.length > 0;

    // Moderator-only login: no streamer row is created.
    if (isModOnly) {
      console.log(`[AUTH] Moderator login bid=${bid} username=${userInfo.username} channels=${moderatorships.length}`);
      createSession(req, res, bid);
      const ret = stored.returnPath || "/mod";
      // Prefer /mod unless they explicitly asked for something else that isn't dashboard
      if (!ret || ret === "/dashboard") return res.redirect("/mod");
      return res.redirect(ret.startsWith("/") ? ret : "/mod");
    }

    // Upsert streamer in DB (creates with overlay_key if new, preserves key if existing)
    const streamer = getDb().upsertStreamer({
      broadcaster_id: bid,
      kick_username: userInfo.username,
      display_name: userInfo.display_name,
      access_token: encrypt(withExpiry.access_token, env.ENCRYPTION_KEY),
      refresh_token: encrypt(withExpiry.refresh_token, env.ENCRYPTION_KEY),
      token_expires_at: withExpiry.expires_at,
      token_scope: withExpiry.scope || null,
    });

    console.log(`[AUTH] ${existing ? "Returning" : "New"} streamer bid=${bid} username=${userInfo.username}`);

    createSession(req, res, bid);
    const ret = stored.returnPath || "/dashboard";
    // If they only asked for /mod and they have moderatorships, honor it
    if (ret === "/mod" && moderatorships.length > 0) {
      return res.redirect("/mod");
    }
    res.redirect(ret);
  } catch (e) {
    console.error("Auth error:", e);
    res.status(500).send("Auth failed");
  }
});

// DEV manual login
router.get("/auth/dev-login", (req, res) => {
  if (env.NODE_ENV === "production") return res.status(403).send("Forbidden in production");
  if (!env.DEV_BYPASS_AUTH) return res.status(403).send("DEV_BYPASS_AUTH not enabled");
  if (env.DEV_BYPASS_KEY && String(req.query.key || "") !== env.DEV_BYPASS_KEY) return res.status(401).send("Invalid dev bypass key");
  if (env.DEV_BYPASS_IPS.length) {
    const ip = (req.ip || "").replace("::ffff:", "");
    if (!env.DEV_BYPASS_IPS.includes(ip)) return res.status(403).send("IP not allowed");
  }
  const bid = Number(req.query.bid || env.DEV_FAKE_BID || 999999);
  if (!Number.isFinite(bid)) return res.status(400).send("Bad bid");

  // Ensure dev streamer exists
  let streamer = getDb().getStreamerById(bid);
  if (!streamer) {
    streamer = getDb().upsertStreamer({
      broadcaster_id: bid,
      kick_username: "dev_user",
      display_name: "Dev User",
      access_token: null,
      refresh_token: null,
    });
  }

  createSession(req, res, bid);
  const ret = safeReturnPath(req.query.ret);
  console.warn(`[AUTH][DEV] Manual dev-login bid=${bid}`);
  return res.redirect(ret);
});

// ── Logout ────────────────────────────────────────────────────────
import { clearSessionCookie } from "../utils/cookies.js";

router.get("/auth/logout", (req, res) => {
  revokeCurrentSession(req, res);
  res.redirect("/");
});

router.post("/auth/logout", (req, res) => {
  revokeCurrentSession(req, res);
  res.json({ ok: true, redirect: "/" });
});

router.get("/account/sessions", requireSession, (req, res) => {
  const sessions = getDb().listSessions(req.session.broadcaster_user_id).map((session) => ({
    created_at: session.created_at,
    last_seen_at: session.last_seen_at,
    expires_at: session.expires_at,
    user_agent: session.user_agent,
    current: session.token_hash === req.session.tokenHash,
  }));
  res.json({ ok: true, sessions });
});

router.post("/auth/logout-all", requireSession, (req, res) => {
  const revoked = getDb().revokeAllSessions(req.session.broadcaster_user_id);
  clearSessionCookie(res);
  res.json({ ok: true, revoked, redirect: "/" });
});

export default router;
