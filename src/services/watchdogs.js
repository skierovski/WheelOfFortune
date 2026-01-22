import { ensureAccessToken, tokenStore } from "./tokens.js";
import { getBroadcasterId, listSubscriptions, subscribeToEvents } from "./kick.js";

let LAST_CALLBACK_URL = null; // ustawiane w /setup

export function setLastCallbackUrl(url) { LAST_CALLBACK_URL = url; }

async function ensureSubscribed() {
  try {
    if (!LAST_CALLBACK_URL) return; // jeszcze nie wiemy jaki jest publiczny callback — odwiedź /setup
    await ensureAccessToken();
    const bid = await getBroadcasterId();
    const subs = await listSubscriptions(bid);
    const hasGifts = subs.some(s => s?.name === "channel.subscription.gifts");
    if (!hasGifts) {
      console.log("[SUBSCRIBE][watchdog] missing gifts sub -> creating");
      await subscribeToEvents(bid, LAST_CALLBACK_URL);
    } else {
      console.log("[SUBSCRIBE][watchdog] OK (gifts sub exists)");
    }
  } catch (e) {
    console.warn("[SUBSCRIBE][watchdog] error:", e?.message || e);
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
  setInterval(ensureSubscribed, 10 * 60 * 1000);
  setInterval(refreshIfSoon,   2  * 60 * 1000);
}

export const watchdogState = { setLastCallbackUrl };
