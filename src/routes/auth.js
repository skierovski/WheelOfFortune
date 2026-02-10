import { Router } from "express";
import { env } from "../utils/env.js";
import { setSessionCookie } from "../utils/cookies.js";
import { KickAuthClient } from "kick-auth";
import { fetchUserInfo } from "../services/kick.js";
import { saveTokens, tokenStore } from "../services/tokens.js";
import { getDb } from "../db.js";
import { encrypt } from "../utils/crypto.js";

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
const authState = new Map();

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
      setSessionCookie(res, fake);
      const ret = String(req.query.ret || "/dashboard");
      console.warn(`[AUTH][DEV] Skip OAuth -> fake session ${fake}, redirect ${ret}`);
      return res.redirect(ret);
    }

    // Validate invite code if required
    const inviteCode = req.query.invite || null;
    if (env.REQUIRE_INVITE) {
      if (!inviteCode) {
        return res.status(400).send("Invite code required. Use /auth/login?invite=YOUR_CODE");
      }
      const validation = getDb().validateInviteCode(inviteCode);
      if (!validation.valid) {
        return res.status(400).send(`Invalid invite code: ${validation.reason}`);
      }
    }

    const desiredScopes = [
      "user:read",
      "channel:read",
      "channel:write",
      "channel:rewards:read",
      "channel:rewards:write",
      "chat:write",
      "streamkey:read",
      "events:subscribe",
      "moderation:ban",
      "moderation:chat_message:manage",
      "kicks:read",
    ];
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
    const ret = String(req.query.ret || "/dashboard");
    url += `&state_ret=${encodeURIComponent(ret)}`;

    // Store state for callback
    authState.set(state, { codeVerifier, redirectUri, inviteCode });

    res.redirect(url);
  } catch (e) {
    console.error("Auth init error:", e);
    res.status(500).send("Failed to start auth");
  }
});

router.get("/auth/callback", async (req, res) => {
  try {
    const { code, state, state_ret } = req.query;
    if (!code || !state) return res.status(400).send("Missing code/state");

    const stored = authState.get(state);
    if (!stored?.codeVerifier || !stored?.redirectUri) return res.status(400).send("Invalid state");
    authState.delete(state);

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

    // For new streamers, validate and consume invite code
    if (!existing && env.REQUIRE_INVITE) {
      const inviteCode = stored.inviteCode;
      if (!inviteCode) {
        return res.status(400).send("Invite code required for new registration");
      }
      const validation = getDb().validateInviteCode(inviteCode);
      if (!validation.valid) {
        return res.status(400).send(`Invalid invite code: ${validation.reason}`);
      }
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

    // Mark invite code as used (for new streamers)
    if (!existing && stored.inviteCode) {
      getDb().useInviteCode(stored.inviteCode, bid);
      console.log(`[AUTH] Invite code used by bid=${bid}`);
    }

    console.log(`[AUTH] ${existing ? "Returning" : "New"} streamer bid=${bid} username=${userInfo.username} overlay_key=${streamer.overlay_key}`);

    setSessionCookie(res, bid);
    const ret = String(state_ret || req.query.ret || "/dashboard");
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

  setSessionCookie(res, bid);
  const ret = String(req.query.ret || "/dashboard");
  console.warn(`[AUTH][DEV] Manual dev-login bid=${bid} -> redirect ${ret}`);
  return res.redirect(ret);
});

// ── Logout ────────────────────────────────────────────────────────
import { clearSessionCookie } from "../utils/cookies.js";

router.get("/auth/logout", (req, res) => {
  clearSessionCookie(res);
  res.redirect("/");
});

export default router;
