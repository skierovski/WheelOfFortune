import { ensureAccessToken, tokenStore } from "./tokens.js";
import { getBroadcasterId, listSubscriptions, subscribeToEvents } from "./kick.js";
import { env } from "../utils/env.js";

let LAST_CALLBACK_URL = null; // ustawiane w /setup

export function setLastCallbackUrl(url) { LAST_CALLBACK_URL = url; }

// Auto-detect callback URL from environment or config
function getCallbackUrl() {
  if (LAST_CALLBACK_URL) return LAST_CALLBACK_URL;
  
  // Try to construct from KICK_REDIRECT_URI (same domain usually)
  if (env.KICK_REDIRECT_URI) {
    try {
      const url = new URL(env.KICK_REDIRECT_URI);
      const callback = `${url.protocol}//${url.host}/webhook`;
      console.log("[WATCHDOG] Auto-detected callback URL:", callback);
      return callback;
    } catch {}
  }
  
  return null;
}

async function ensureSubscribed() {
  try {
    const callbackUrl = getCallbackUrl();
    if (!callbackUrl) {
      console.log("[SUBSCRIBE][watchdog] No callback URL yet - visit /setup to configure");
      return;
    }
    
    await ensureAccessToken();
    const bid = await getBroadcasterId();
    const subs = await listSubscriptions(bid);
    const hasGifts = subs.some(s => s?.name === "channel.subscription.gifts" && s?.callback === callbackUrl);
    
    if (!hasGifts) {
      console.log("[SUBSCRIBE][watchdog] ⚠️ Missing or outdated subscription -> creating");
      console.log("[SUBSCRIBE][watchdog] Callback URL:", callbackUrl);
      await subscribeToEvents(bid, callbackUrl);
      console.log("[SUBSCRIBE][watchdog] ✅ Subscription created successfully");
    } else {
      console.log("[SUBSCRIBE][watchdog] ✅ OK (gifts subscription exists)");
    }
  } catch (e) {
    console.warn("[SUBSCRIBE][watchdog] ❌ Error:", e?.message || e);
  }
}

/* Watchdog tokenów – co 2 min, jeśli do końca < 15 min, odśwież */
async function refreshIfSoon() {
  try {
    const t = tokenStore.loadTokens();
    if (!t?.refresh_token) return;
    const left = Math.floor((t.expires_at - Date.now())/1000);
    if (!Number.isFinite(left) || left <= 15*60) {
      console.log(`[tokens] watchdog refresh (left ${left}s)`);
      // ensureAccessToken() wykona odświeżenie
      await ensureAccessToken();
    }
  } catch (e) {
    console.warn("[tokens] watchdog error:", e?.message || e);
  }
}

export function startWatchdogs() {
  console.log("[WATCHDOG] 🚀 Starting watchdogs...");
  
  // Run subscription check immediately on startup
  setTimeout(ensureSubscribed, 5000); // 5 seconds after server starts
  
  // Then check every 5 minutes (was 10 minutes)
  setInterval(ensureSubscribed, 5 * 60 * 1000);
  
  // Token refresh watchdog - every 2 minutes
  setInterval(refreshIfSoon, 2 * 60 * 1000);
  
  console.log("[WATCHDOG] ✅ Watchdogs started (subscription check in 5s, then every 5min)");
}

export const watchdogState = { 
  setLastCallbackUrl,
  ensureSubscribed // expose for manual triggering
};
