import { getSessionBroadcasterId, setSessionCookie } from "../utils/cookies.js";
import { env } from "../utils/env.js";

function isDevBypassAllowed(req) {
  if (env.NODE_ENV === "production") return false;
  if (!env.DEV_BYPASS_AUTH) return false;
  if (env.DEV_BYPASS_IPS.length) {
    const ip = (req.ip || "").replace("::ffff:", "");
    if (!env.DEV_BYPASS_IPS.includes(ip)) return false;
  }
  return true;
}

export function requireSession(req, res, next) {
  const bid = getSessionBroadcasterId(req);
  if (bid) { req.session = { broadcaster_user_id: bid }; return next(); }
  if (isDevBypassAllowed(req)) {
    const fake = Number.isFinite(env.DEV_FAKE_BID) ? env.DEV_FAKE_BID : 999999;
    console.warn(`[AUTH][DEV] Bypass → fake session broadcaster_user_id=${fake}`);
    setSessionCookie(res, fake);
    req.session = { broadcaster_user_id: fake };
    return next();
  }
  const base = `${(req.headers["x-forwarded-proto"] || req.protocol || "http").split(",")[0].trim()}://${(req.headers["x-forwarded-host"] || req.get("host")).split(",")[0].trim()}`;
  const ret = encodeURIComponent(req.originalUrl || "/home");
  return res.redirect(`${base}/auth/login?ret=${ret}`);
}
