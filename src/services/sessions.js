import crypto from "crypto";
import { getDb } from "../db.js";
import { clearSessionCookie, parseCookies, sessionTokenHash, setSessionCookie } from "../utils/cookies.js";

const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;

function privacyHash(value) {
  if (!value) return null;
  return crypto.createHmac("sha256", "session-metadata").update(String(value)).digest("hex");
}

export function createSession(req, res, broadcasterId, now = Date.now()) {
  const token = crypto.randomBytes(32).toString("base64url");
  const tokenHash = sessionTokenHash(token);
  getDb().createSession({
    token_hash: tokenHash,
    broadcaster_id: Number(broadcasterId),
    csrf_secret: crypto.randomBytes(32).toString("base64url"),
    created_at: now,
    last_seen_at: now,
    expires_at: now + SESSION_TTL_MS,
    user_agent: String(req?.get?.("user-agent") || "").slice(0, 255) || null,
    ip_hash: privacyHash(req?.ip),
  });
  setSessionCookie(res, token);
  return getDb().getSession(tokenHash, now);
}

export function resolveSession(req, now = Date.now()) {
  const token = parseCookies(req).wheel_sess;
  if (!token) return null;
  const tokenHash = sessionTokenHash(token);
  const session = getDb().getSession(tokenHash, now);
  if (!session) return null;
  if (now - session.last_seen_at > 5 * 60 * 1000) getDb().touchSession(tokenHash, now);
  return { ...session, tokenHash };
}

export function revokeCurrentSession(req, res, now = Date.now()) {
  const token = parseCookies(req).wheel_sess;
  if (token) getDb().revokeSession(sessionTokenHash(token), now);
  clearSessionCookie(res);
}
