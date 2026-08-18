import { env } from "../utils/env.js";

const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);
const PROTECTED_PREFIXES = ["/dashboard", "/mod", "/auth/logout"];

function canonicalOrigin(value) {
  try {
    return new URL(value).origin;
  } catch {
    return null;
  }
}

export function csrfProtection(req, res, next) {
  if (SAFE_METHODS.has(req.method)) return next();
  if (!PROTECTED_PREFIXES.some((prefix) => req.path === prefix || req.path.startsWith(`${prefix}/`))) {
    return next();
  }

  const origin = canonicalOrigin(req.get("origin"));
  const expected = canonicalOrigin(env.PUBLIC_BASE_URL) || canonicalOrigin(`${req.protocol}://${req.get("host")}`);
  const fetchSite = String(req.get("sec-fetch-site") || "").toLowerCase();
  const sameOrigin = origin && expected && origin === expected;

  if (sameOrigin && (!fetchSite || fetchSite === "same-origin")) return next();
  if (env.NODE_ENV !== "production" && !origin && !fetchSite) return next();
  return res.status(403).json({ ok: false, error: "Request origin rejected" });
}
