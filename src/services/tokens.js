import { env } from "../utils/env.js";
import { encrypt, decrypt } from "../utils/crypto.js";
import { getDb } from "../db.js";

const SKEW_MS = 60_000 * 15; // 15-minute safety margin

/** In-flight refresh promises keyed by broadcaster_id (serialize Kick refresh rotation). */
const refreshInFlight = new Map();

/**
 * Compute expires_at from expires_in, applying a 15-minute skew.
 */
function withExpiresAt(tokens) {
  if (!tokens) return null;
  if (Number.isFinite(tokens.expires_in)) {
    tokens.expires_at = Date.now() + (Number(tokens.expires_in) * 1000) - SKEW_MS;
  }
  return tokens;
}

/**
 * Seconds until the token expires (negative = already expired).
 */
function secondsUntilExpiry(expiresAt) {
  if (!Number.isFinite(expiresAt)) return -Infinity;
  return Math.floor((expiresAt - Date.now()) / 1000);
}

function isInvalidGrantError(status, bodyText) {
  if (status !== 400 && status !== 401) return false;
  try {
    const j = JSON.parse(bodyText);
    return j?.error === "invalid_grant";
  } catch {
    return /invalid_grant/i.test(bodyText || "");
  }
}

/**
 * Refresh the access token using Kick's OAuth endpoint.
 */
async function refreshAccessTokenFromKick(refreshToken) {
  const body = new URLSearchParams();
  body.set("grant_type", "refresh_token");
  body.set("client_id", env.KICK_CLIENT_ID);
  body.set("client_secret", env.KICK_CLIENT_SECRET);
  body.set("refresh_token", refreshToken || "");
  const r = await fetch(`${env.KICK_OAUTH_HOST}/oauth/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });
  const text = await r.text();
  if (!r.ok) {
    const err = new Error(`refresh failed: ${r.status} ${text}`);
    err.status = r.status;
    err.body = text;
    err.invalidGrant = isInvalidGrantError(r.status, text);
    throw err;
  }
  return JSON.parse(text);
}

// ── Per-streamer token operations ────────────────────────────────

/**
 * Load tokens for a streamer (decrypted).
 * @param {number} broadcasterId
 * @returns {{ access_token: string, refresh_token: string, expires_at: number, scope: string } | null}
 */
export function loadTokens(broadcasterId) {
  const streamer = getDb().getStreamerById(broadcasterId);
  if (!streamer?.access_token) return null;
  try {
    return {
      access_token: decrypt(streamer.access_token, env.ENCRYPTION_KEY),
      refresh_token: decrypt(streamer.refresh_token, env.ENCRYPTION_KEY),
      expires_at: streamer.token_expires_at,
      scope: streamer.token_scope,
    };
  } catch (e) {
    console.error(`[tokens] Failed to decrypt tokens for broadcaster ${broadcasterId}:`, e.message);
    return null;
  }
}

/**
 * Save tokens for a streamer (encrypted).
 * @param {number} broadcasterId
 * @param {{ access_token: string, refresh_token: string, expires_at?: number, expires_in?: number, scope?: string }} tokens
 */
export function saveTokens(broadcasterId, tokens) {
  const withExpiry = withExpiresAt({ ...tokens });
  getDb().updateTokens(broadcasterId, {
    access_token: encrypt(withExpiry.access_token, env.ENCRYPTION_KEY),
    refresh_token: encrypt(withExpiry.refresh_token, env.ENCRYPTION_KEY),
    token_expires_at: withExpiry.expires_at ?? null,
    token_scope: withExpiry.scope ?? null,
  });
  console.log(`[tokens] saved for broadcaster ${broadcasterId}:`, {
    access_token: env.mask(tokens.access_token),
    refresh_token: env.mask(tokens.refresh_token),
    expires_at: withExpiry.expires_at,
    scope: withExpiry.scope,
  });
}

/**
 * Clear stored OAuth tokens so watchdogs stop retrying until the user re-logs in.
 * @param {number} broadcasterId
 */
export function clearTokens(broadcasterId) {
  getDb().updateTokens(broadcasterId, {
    access_token: null,
    refresh_token: null,
    token_expires_at: null,
    token_scope: null,
  });
  console.warn(`[tokens] cleared dead tokens for broadcaster ${broadcasterId} — re-login via /auth/login required`);
}

/**
 * Ensure a valid access token is available for a streamer.
 * Refreshes automatically if expiring within 15 minutes.
 * Concurrent refreshes for the same bid are serialized (Kick rotates refresh tokens).
 * @param {number} broadcasterId
 * @returns {Promise<string>} access_token
 */
export async function ensureAccessToken(broadcasterId) {
  const existing = refreshInFlight.get(broadcasterId);
  if (existing) return existing;

  const run = (async () => {
    const tokens = loadTokens(broadcasterId);
    if (!tokens?.access_token) {
      throw new Error(`No tokens stored for broadcaster ${broadcasterId}. Needs re-login via /auth/login`);
    }
    const left = secondsUntilExpiry(tokens.expires_at);
    if (!Number.isFinite(left) || left <= 15 * 60) {
      if (!tokens.refresh_token) {
        throw new Error(`No refresh_token for broadcaster ${broadcasterId}`);
      }
      console.log(`[tokens] refreshing for ${broadcasterId} (left ${left}s)`);
      try {
        const refreshed = await refreshAccessTokenFromKick(tokens.refresh_token);
        const merged = withExpiresAt({ ...tokens, ...refreshed });
        saveTokens(broadcasterId, merged);
        return merged.access_token;
      } catch (e) {
        if (e?.invalidGrant) {
          clearTokens(broadcasterId);
          throw new Error(
            `Refresh token revoked/expired for broadcaster ${broadcasterId}. Streamer must re-login via /auth/login`
          );
        }
        throw e;
      }
    }
    return tokens.access_token;
  })();

  refreshInFlight.set(broadcasterId, run);
  try {
    return await run;
  } finally {
    refreshInFlight.delete(broadcasterId);
  }
}

// ── Exported for backward compatibility and watchdog use ─────────

export const tokenStore = {
  loadTokens,
  saveTokens,
  clearTokens,
  withExpiresAt,
  secondsUntilExpiry,
};
