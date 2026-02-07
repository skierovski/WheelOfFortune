import fs from "fs";
import path from "path";
import { ensureAccessToken, tokenStore } from "./tokens.js";
import { getBroadcasterId, listSubscriptions, subscribeToEvents } from "./kick.js";
import { env } from "../utils/env.js";

let LAST_CALLBACK_URL = null;

const CALLBACK_URL_PATH = process.env.CALLBACK_URL_FILE || path.join(path.dirname(env.TOK_PATH), ".callback_url");

function loadPersistedCallbackUrl() {
  try {
    const s = fs.readFileSync(CALLBACK_URL_PATH, "utf8").trim();
    if (s) return s;
  } catch {}
  return null;
}

function saveCallbackUrl(url) {
  if (!url?.trim()) return;
  try {
    fs.mkdirSync(path.dirname(CALLBACK_URL_PATH), { recursive: true });
    fs.writeFileSync(CALLBACK_URL_PATH, url.trim(), "utf8");
  } catch (e) {
    console.warn("[WATCHDOG] Could not persist callback URL:", e?.message);
  }
}

export function setLastCallbackUrl(url) {
  LAST_CALLBACK_URL = url;
  if (url) saveCallbackUrl(url);
}

// Callback URL: memory → persisted file → PUBLIC_BASE_URL → KICK_REDIRECT_URI derived
function getCallbackUrl() {
  if (LAST_CALLBACK_URL) return LAST_CALLBACK_URL;

  const fromFile = loadPersistedCallbackUrl();
  if (fromFile) return fromFile;

  if (env.PUBLIC_BASE_URL) {
    const base = env.PUBLIC_BASE_URL.replace(/\/$/, "");
    const callback = base.includes("/webhook") ? base : `${base}/webhook`;
    return callback;
  }

  if (env.KICK_REDIRECT_URI) {
    try {
      const u = new URL(env.KICK_REDIRECT_URI);
      return `${u.protocol}//${u.host}/webhook`;
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
  
  // Re-subscribe soon after startup (tokens + callback URL from disk/env)
  setTimeout(ensureSubscribed, 2000);

  setInterval(ensureSubscribed, 5 * 60 * 1000);
  setInterval(refreshIfSoon, 2 * 60 * 1000);

  console.log("[WATCHDOG] ✅ Watchdogs started (subscription in 2s, then every 5min)");
}

export const watchdogState = { 
  setLastCallbackUrl,
  ensureSubscribed // expose for manual triggering
};
