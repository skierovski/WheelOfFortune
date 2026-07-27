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

  const REQUIRED_EVENTS = [
    "channel.subscription.gifts",
    "channel.subscription.new",
    "channel.subscription.renewal",
    "chat.message.sent",
  ];

  for (const streamer of streamers) {
    if (!streamer.access_token) continue;

    try {
      const bid = streamer.broadcaster_id;
      const subs = await listSubscriptions(bid);

      const missingEvents = REQUIRED_EVENTS.filter(
        (evt) => !subs.some((s) => s?.name === evt && s?.callback === callbackUrl)
      );

      if (missingEvents.length > 0) {
        console.log(`[WATCHDOG] bid=${bid} missing events: ${missingEvents.join(", ")} -> subscribing`);
        const events = missingEvents.map((name) => ({ name, version: 1 }));
        await subscribeToEvents(bid, callbackUrl, events);

        const db = getDb();
        for (const evt of missingEvents) {
          db.addSubscription(bid, {
            subscription_id: "auto",
            event_type: evt,
            callback_url: callbackUrl,
          });
        }
        console.log(`[WATCHDOG] bid=${bid} subscriptions created: ${missingEvents.join(", ")}`);
      }
    } catch (e) {
      const msg = e?.message || String(e);
      if (/re-login/i.test(msg)) {
        console.warn(`[WATCHDOG] bid=${streamer.broadcaster_id} skipped (needs re-login)`);
      } else {
        console.warn(`[WATCHDOG] bid=${streamer.broadcaster_id} subscription error:`, msg);
      }
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
      const msg = e?.message || String(e);
      if (/re-login|revoked\/expired/i.test(msg)) {
        console.warn(`[WATCHDOG] bid=${streamer.broadcaster_id} tokens cleared — streamer must re-login`);
      } else {
        console.warn(`[WATCHDOG] bid=${streamer.broadcaster_id} token refresh error:`, msg);
      }
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
