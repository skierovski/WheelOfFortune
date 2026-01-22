import { Router } from "express";
import { env } from "../utils/env.js";
import { setSessionCookie } from "../utils/cookies.js";
import { KickAuthClient } from "kick-auth";
import { getBroadcasterId } from "../services/kick.js";
import { tokenStore } from "../services/tokens.js";

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

router.get("/auth/login", async (req, res) => {
  try {
    if (isDevBypassAllowed(req)) {
      const fake = Number.isFinite(env.DEV_FAKE_BID) ? env.DEV_FAKE_BID : 999999;
      setSessionCookie(res, fake);
      const ret = String(req.query.ret || "/home");
      console.warn(`[AUTH][DEV] Skip OAuth → set fake session ${fake}, redirect ${ret}`);
      return res.redirect(ret);
    }

    const desiredScopes = ["user:read","channel:read","channel:write","chat:write","events:subscribe"];
    const redirectUri = env.KICK_REDIRECT_URI || `${req.protocol}://${req.get("host")}/auth/callback`;
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
    const ret = String(req.query.ret || "/home");
    url += `&state_ret=${encodeURIComponent(ret)}`;

    // pamiętamy w prostym cache w pamięci (Map na module)
    authState.set(state, { codeVerifier, redirectUri });

    res.redirect(url);
  } catch (e) {
    console.error("Auth init error:", e);
    res.status(500).send("Failed to start auth");
  }
});

const authState = new Map();

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
    const saved = tokenStore.withExpiresAt(tokens);
    tokenStore.saveTokens(saved);

    const bid = await getBroadcasterId();
    setSessionCookie(res, bid);

    const ret = String(state_ret || req.query.ret || "/home");
    res.redirect(ret);
  } catch (e) {
    console.error("Auth error:", e);
    res.status(500).send("Auth failed");
  }
});

// DEV ręczne logowanie
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
  setSessionCookie(res, bid);
  const ret = String(req.query.ret || "/home");
  console.warn(`[AUTH][DEV] Manual dev-login set broadcaster_user_id=${bid} → redirect ${ret}`);
  return res.redirect(ret);
});

export default router;
