import fs from "fs";
import path from "path";
import { env } from "../utils/env.js";

let PENDING_SPINS_COUNT = 0;
let broadcastFn = null;
let lastSpinTime = 0;
let spinInProgress = false; // Track if a spin is currently happening
const SPIN_DELAY_MS = 5 * 60 * 1000; // 5 minutes

// Persistent storage for pending spins (survives server restarts)
function ensureDirFor(filePath) {
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

function loadPendingSafe() {
  try {
    if (!fs.existsSync(env.PENDING_PATH)) return 0;
    const n = JSON.parse(fs.readFileSync(env.PENDING_PATH, "utf8"));
    return Math.max(0, Number(n) || 0);
  } catch { return 0; }
}

function savePendingSafe(n) {
  ensureDirFor(env.PENDING_PATH);
  try {
    fs.writeFileSync(env.PENDING_PATH, JSON.stringify(Math.max(0, Number(n) || 0)));
  } catch (e) {
    console.warn("[pending] save failed:", e.message);
  }
}

// Load pending spins on startup
PENDING_SPINS_COUNT = loadPendingSafe();
if (PENDING_SPINS_COUNT > 0) {
  console.log(`[spins] Loaded ${PENDING_SPINS_COUNT} pending spins from disk`);
}

function addPending(n) {
  const x = Number(n) || 0;
  if (x > 0) {
    PENDING_SPINS_COUNT += x;
    savePendingSafe(PENDING_SPINS_COUNT);
    console.log(`[spins] pending += ${x}  (total=${PENDING_SPINS_COUNT})`);
  }
}

function consumePending(n) {
  const want = Math.max(0, Number(n) || 0);
  const take = Math.min(PENDING_SPINS_COUNT, want);
  PENDING_SPINS_COUNT -= take;
  savePendingSafe(PENDING_SPINS_COUNT);
  console.log(`[spins] consumed ${take}  (left=${PENDING_SPINS_COUNT})`);
  return take;
}

function broadcast(obj) {
  if (!broadcastFn) return 0;
  return broadcastFn(obj) || 0;
}

function getTimeUntilNextSpin() {
  const now = Date.now();
  const elapsed = now - lastSpinTime;
  if (elapsed >= SPIN_DELAY_MS) return 0;
  return SPIN_DELAY_MS - elapsed;
}

export const spins = {
  getPending: () => PENDING_SPINS_COUNT,
  getTimeUntilNextSpin,
  setBroadcaster: (fn) => { broadcastFn = fn; },
  deliverSpinOrQueue(times) {
    const safe = Math.max(0, Number(times) || 0);
    if (!safe) return 0;
    
    // Always queue the spins first (don't deliver all at once)
    addPending(safe);
    console.log(`[SPIN] queued +${safe} (total pending=${PENDING_SPINS_COUNT})`);
    
    // If a spin is already in progress, just queue and return
    if (spinInProgress) {
      broadcast({ 
        type: "delay", 
        timeUntilNext: Math.ceil(getTimeUntilNextSpin() / 1000),
        pending: PENDING_SPINS_COUNT 
      });
      return 0;
    }
    
    // Check if we can deliver the first spin now
    const timeUntilNext = getTimeUntilNextSpin();
    
    if (timeUntilNext > 0) {
      // Delay not passed yet - just queue (already done above)
      broadcast({ 
        type: "delay", 
        timeUntilNext: Math.ceil(timeUntilNext / 1000),
        pending: PENDING_SPINS_COUNT 
      });
      return 0;
    }
    
    // Delay passed - deliver ONE spin (not all of them)
    const toDeliver = Math.min(PENDING_SPINS_COUNT, 1); // Only deliver 1 at a time
    const taken = consumePending(toDeliver);
    if (taken > 0) {
      spinInProgress = true;
      const delivered = broadcast({ action: "spin", times: 1 }); // Always deliver 1 spin
      if (delivered > 0) {
        console.log(`[SPIN] delivered 1 spin (${PENDING_SPINS_COUNT} remaining, will wait 5min after completion)`);
      } else {
        // No clients connected, put it back in queue
        spinInProgress = false;
        addPending(taken);
        console.log(`[SPIN] no clients, requeued (pending=${PENDING_SPINS_COUNT})`);
      }
      return delivered;
    }
    
    return 0;
  },
  addPending,
  consumePending,
  markSpinComplete() {
    spinInProgress = false;
    lastSpinTime = Date.now(); // Start 5-minute delay timer from now
    console.log(`[SPIN] completed - delay timer started (next spin in 5 minutes)`);
    
    // Check if there are pending spins that can now be delivered
    if (PENDING_SPINS_COUNT > 0) {
      const timeUntilNext = getTimeUntilNextSpin();
      if (timeUntilNext === 0) {
        // This shouldn't happen since we just set lastSpinTime, but handle it anyway
        const toDeliver = Math.min(PENDING_SPINS_COUNT, 1);
        const taken = consumePending(toDeliver);
        if (taken > 0) {
          spinInProgress = true;
          broadcast({ action: "spin", times: taken });
          console.log(`[SPIN] delivered pending ${taken} (remaining=${PENDING_SPINS_COUNT})`);
        }
      } else {
        // Need to wait 5 minutes - broadcast delay info
        broadcast({ 
          type: "delay", 
          timeUntilNext: Math.ceil(timeUntilNext / 1000),
          pending: PENDING_SPINS_COUNT 
        });
        console.log(`[SPIN] ${PENDING_SPINS_COUNT} pending spin(s) will wait ${Math.ceil(timeUntilNext/1000)}s`);
      }
    }
  }
};

// Check periodically if pending spins can be delivered
setInterval(() => {
  if (PENDING_SPINS_COUNT > 0 && !spinInProgress) {
    const timeUntilNext = getTimeUntilNextSpin();
    if (timeUntilNext === 0) {
      const toDeliver = Math.min(PENDING_SPINS_COUNT, 1);
      const taken = consumePending(toDeliver);
      if (taken > 0) {
        spinInProgress = true;
        broadcast({ action: "spin", times: taken });
        console.log(`[SPIN][timer] delivered pending ${taken} (remaining=${PENDING_SPINS_COUNT})`);
      }
    } else {
      // Broadcast delay update
      broadcast({ 
        type: "delay", 
        timeUntilNext: Math.ceil(timeUntilNext / 1000),
        pending: PENDING_SPINS_COUNT 
      });
    }
  }
}, 1000); // Check every second

// Save pending on exit
process.on("SIGTERM", () => { savePendingSafe(PENDING_SPINS_COUNT); process.exit(0); });
process.on("SIGINT", () => { savePendingSafe(PENDING_SPINS_COUNT); process.exit(0); });

export function wsBroadcast(msg) {
    return broadcast(msg);
}
