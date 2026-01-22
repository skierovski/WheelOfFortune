import fs from "fs";
import { env } from "../utils/env.js";

function loadTokens() {
  try { return JSON.parse(fs.readFileSync(env.TOK_PATH, "utf8")); } catch { return null; }
}
function saveTokens(t) {
  fs.writeFileSync(env.TOK_PATH, JSON.stringify(t, null, 2));
  console.log("[tokens] saved:", {
    access_token: env.mask(t.access_token),
    refresh_token: env.mask(t.refresh_token),
    expires_at: t.expires_at,
    scope: t.scope,
  });
}
function withExpiresAt(tokens) {
  if (!tokens) return null;
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
async function refreshAccessTokenManual(refreshToken) {
  const body = new URLSearchParams();
  body.set("grant_type", "refresh_token");
  body.set("client_id", env.KICK_CLIENT_ID);
  body.set("client_secret", env.KICK_CLIENT_SECRET);
  body.set("refresh_token", refreshToken || "");
  const r = await fetch(`${env.KICK_OAUTH_HOST}/oauth/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body
  });
  const text = await r.text();
  if (!r.ok) throw new Error(`refresh failed: ${r.status} ${text}`);
  return JSON.parse(text);
}

export async function ensureAccessToken() {
  let tokens = loadTokens();
  if (!tokens?.access_token) throw new Error("No tokens stored. Log in via /auth/login");
  const left = secondsUntilExpiry(tokens);
  if (!Number.isFinite(left) || left <= 15 * 60) {
    if (!tokens.refresh_token) throw new Error("No refresh_token stored");
    console.log(`[tokens] refreshing (left ${left}s) manual /oauth/token`);
    const refreshed = await refreshAccessTokenManual(tokens.refresh_token);
    const merged = withExpiresAt({ ...tokens, ...refreshed });
    saveTokens(merged);
    return merged.access_token;
  }
  return tokens.access_token;
}
export const tokenStore = { loadTokens, saveTokens, withExpiresAt };
