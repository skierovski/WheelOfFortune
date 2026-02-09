import { getSessionBroadcasterId, setSessionCookie } from "../utils/cookies.js";
import { env } from "../utils/env.js";
import { getDb } from "../db.js";

function isDevBypassAllowed(req) {
  if (env.NODE_ENV === "production") return false;
  if (!env.DEV_BYPASS_AUTH) return false;
  if (env.DEV_BYPASS_IPS.length) {
    const ip = (req.ip || "").replace("::ffff:", "");
    if (!env.DEV_BYPASS_IPS.includes(ip)) return false;
  }
  return true;
}

/**
 * Middleware: requires a valid session cookie.
 * Sets req.session = { broadcaster_user_id, streamer } on success.
 */
export async function requireSession(req, res, next) {
  const bid = getSessionBroadcasterId(req);
  if (bid) {
    const streamer = getDb().getStreamerById(bid);
    if (streamer) {
      req.session = { broadcaster_user_id: bid, streamer };
      return next();
    }
    // Cookie is valid but streamer not in DB -- clear it
  }

  if (isDevBypassAllowed(req)) {
    const fake = Number.isFinite(env.DEV_FAKE_BID) ? env.DEV_FAKE_BID : 999999;
    // Ensure dev streamer exists in DB
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
    console.warn(`[AUTH][DEV] Bypass -> fake session bid=${fake}`);
    setSessionCookie(res, fake);
    req.session = { broadcaster_user_id: fake, streamer };
    return next();
  }

  const base = `${(req.headers["x-forwarded-proto"] || req.protocol || "http").split(",")[0].trim()}://${(req.headers["x-forwarded-host"] || req.get("host")).split(",")[0].trim()}`;
  const ret = encodeURIComponent(req.originalUrl || "/dashboard");
  return res.redirect(`${base}/auth/login?ret=${ret}`);
}

/**
 * Middleware: resolves a broadcaster from overlay_key in URL params.
 * Sets req.streamer on success, returns 404 if key is invalid.
 */
export function resolveOverlayKey(req, res, next) {
  const key = req.params.key;
  if (!key || !/^[A-Za-z0-9_-]+$/.test(key)) {
    return res.status(400).json({ ok: false, error: "Invalid overlay key" });
  }
  const streamer = getDb().getStreamerByOverlayKey(key);
  if (!streamer) {
    return res.status(404).json({ ok: false, error: "Streamer not found" });
  }
  req.streamer = streamer;
  return next();
}
