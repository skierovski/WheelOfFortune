import { ensureAccessToken, loadTokens, tokenStore } from "./tokens.js";
import { listSubscriptions, subscribeToEvents } from "./kick.js";
import { getDb } from "../db.js";
import { env } from "../utils/env.js";

/**
 * Get the webhook callback URL from the environment.
 */
function getCallbackUrl() {
  if (env.PUBLIC_BASE_URL) {
    const base = env.PUBLIC_BASE_URL.replace(/\/$/, "");
    return base.includes("/webhook") ? base : `${base}/webhook`;
  }
  if (env.KICK_REDIRECT_URI) {
    try {
      const u = new URL(env.KICK_REDIRECT_URI);
      return `${u.protocol}//${u.host}/webhook`;
    } catch {}
  }
  return null;
}

/**
 * Check and ensure subscriptions for all streamers.
 */
async function ensureAllSubscriptions() {
  const callbackUrl = getCallbackUrl();
  if (!callbackUrl) {
    console.log("[WATCHDOG] No callback URL configured - skipping subscription check");
    return;
  }

  let streamers;
  try {
    streamers = getDb().getAllStreamers();
  } catch {
    return; // DB not ready
  }

  for (const streamer of streamers) {
    if (!streamer.access_token) continue; // no tokens, skip

    try {
      const bid = streamer.broadcaster_id;
      const subs = await listSubscriptions(bid);
      const hasGifts = subs.some(
        (s) => s?.name === "channel.subscription.gifts" && s?.callback === callbackUrl
      );

      if (!hasGifts) {
        console.log(`[WATCHDOG] bid=${bid} missing subscription -> creating`);
        await subscribeToEvents(bid, callbackUrl);
        
        // Store in DB
        const db = getDb();
        db.deactivateSubscriptions(bid);
        db.addSubscription(bid, {
          subscription_id: "auto",
          event_type: "channel.subscription.gifts",
          callback_url: callbackUrl,
        });
        console.log(`[WATCHDOG] bid=${bid} subscription created`);
      }
    } catch (e) {
      console.warn(`[WATCHDOG] bid=${streamer.broadcaster_id} subscription error:`, e?.message || e);
    }
  }
}

/**
 * Refresh tokens for all streamers nearing expiry.
 */
async function refreshAllTokens() {
  let streamers;
  try {
    streamers = getDb().getAllStreamers();
  } catch {
    return; // DB not ready
  }

  for (const streamer of streamers) {
    if (!streamer.access_token) continue;

    try {
      const bid = streamer.broadcaster_id;
      const tokens = loadTokens(bid);
      if (!tokens?.refresh_token) continue;

      const left = tokenStore.secondsUntilExpiry(tokens.expires_at);
      if (!Number.isFinite(left) || left <= 15 * 60) {
        console.log(`[WATCHDOG] bid=${bid} token expiring (left ${left}s) -> refreshing`);
        await ensureAccessToken(bid);
      }
    } catch (e) {
      console.warn(`[WATCHDOG] bid=${streamer.broadcaster_id} token refresh error:`, e?.message || e);
    }
  }
}

let _subInterval = null;
let _tokInterval = null;

export function startWatchdogs() {
  console.log("[WATCHDOG] Starting watchdogs...");

  // Check subscriptions 2s after startup, then every 5 minutes
  setTimeout(ensureAllSubscriptions, 2000);
  _subInterval = setInterval(ensureAllSubscriptions, 5 * 60 * 1000);

  // Refresh tokens every 2 minutes
  _tokInterval = setInterval(refreshAllTokens, 2 * 60 * 1000);

  console.log("[WATCHDOG] Started (subscriptions every 5min, tokens every 2min)");
}

export function stopWatchdogs() {
  if (_subInterval) { clearInterval(_subInterval); _subInterval = null; }
  if (_tokInterval) { clearInterval(_tokInterval); _tokInterval = null; }
}
