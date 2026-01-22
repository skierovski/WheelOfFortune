import crypto from "crypto";
import { env } from "./env.js";

export function parseCookies(req) {
  const header = req.headers.cookie || "";
  const out = {};
  header.split(";").forEach(p => {
    const i = p.indexOf("=");
    if (i > -1) out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
  });
  return out;
}
export function hmacHex(str) {
  return crypto.createHmac("sha256", env.SESSION_SECRET).update(str, "utf8").digest("hex");
}
export function setSessionCookie(res, broadcasterId) {
  const val = String(broadcasterId);
  const sig = hmacHex(val);
  const cookieVal = `${val}.${sig}`;
  const parts = [
    `wheel_sess=${encodeURIComponent(cookieVal)}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
    "Max-Age=2592000",
  ];
  if (env.NODE_ENV === "production") parts.push("Secure");
  res.setHeader("Set-Cookie", parts.join("; "));
}
export function getSessionBroadcasterId(req) {
  const { wheel_sess } = parseCookies(req);
  if (!wheel_sess) return null;
  const [val, sig] = String(wheel_sess).split(".");
  if (!val || !sig) return null;
  if (hmacHex(val) !== sig) return null;
  const id = Number(val);
  if (!Number.isFinite(id)) return null;
  return id;
}
