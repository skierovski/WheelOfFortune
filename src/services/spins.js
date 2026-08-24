import { getDb } from "../db.js";
import crypto from "crypto";
import { issueOverlayTicket } from "./overlayTickets.js";

const SPIN_DELAY_MS = 5 * 60 * 1000; // 5 minutes

// Broadcast function set by the WebSocket layer: (broadcasterId, msg) => clientCount
let broadcastFn = null;

// In-memory spin-in-progress tracking per streamer (not persisted because
// a restart means no overlay is mid-spin anyway)
const inProgress = new Map();

// In-memory tier queue per streamer: Map<broadcasterId, string[]>
// Stores the tier name for each pending spin so we deliver the right tier
const tierQueues = new Map();

// ── Internal helpers ────────────────────────────────────────────────

function getState(broadcasterId) {
  return getDb().getSpinState(broadcasterId);
}

function setState(broadcasterId, updates) {
  const current = getState(broadcasterId);
  getDb().saveSpinState(broadcasterId, {
    pending_count: updates.pending_count ?? current.pending_count,
    last_spin_time: updates.last_spin_time ?? current.last_spin_time,
    spin_in_progress: updates.spin_in_progress ?? current.spin_in_progress,
  });
}

function isInProgress(broadcasterId) {
  return inProgress.get(broadcasterId) || false;
}

function setInProgress(broadcasterId, value) {
  inProgress.set(broadcasterId, value);
}

function getTimeUntilNextSpin(broadcasterId) {
  const state = getState(broadcasterId);
  const elapsed = Date.now() - (state.last_spin_time || 0);
  if (elapsed >= SPIN_DELAY_MS) return 0;
  return SPIN_DELAY_MS - elapsed;
}

function broadcast(broadcasterId, msg) {
  if (!broadcastFn) return 0;
  return broadcastFn(broadcasterId, msg) || 0;
}

export function selectPrize(items, randomInt = crypto.randomInt) {
  const eligible = (Array.isArray(items) ? items : []).filter((item) => item?.id && Number(item.weight) > 0);
  if (!eligible.length) return null;
  const units = eligible.map((item) => Math.max(0, Math.round(Number(item.weight) * 10)));
  const total = units.reduce((sum, value) => sum + value, 0);
  if (total <= 0) return null;
  let cursor = randomInt(total);
  for (let index = 0; index < eligible.length; index++) {
    cursor -= units[index];
    if (cursor < 0) return eligible[index];
  }
  return eligible[eligible.length - 1];
}

function buildSpinMessage(broadcasterId, tierName, { test = false } = {}) {
  const config = getDb().getConfig(broadcasterId);
  const tier = tierName && Array.isArray(config?.tiers)
    ? config.tiers.find((candidate) => candidate.name === tierName)
    : null;
  const items = tier?.items?.length ? tier.items : config?.items;
  const testItems = test && Array.isArray(items) ? items.filter((item) => !item?.bonus) : items;
  const picked = selectPrize(testItems?.length ? testItems : items);
  const msg = { action: "spin", times: 1 };
  if (test) msg.test = true;
  if (tierName) msg.tier = tierName;
  if (picked) {
    msg.pickedId = String(picked.id);
    msg.ticket = issueOverlayTicket({
      broadcasterId,
      kind: "wheel",
      announceLabel: test ? "" : `${picked.label}${picked.bonus ? " (+bonus)" : ""}${tierName ? ` [${tierName}]` : ""}`,
      metadata: { bonus: test ? false : !!picked.bonus, tier: tierName || null, test },
    });
  }
  return msg;
}

// ── Public API ──────────────────────────────────────────────────────

export const spins = {
  SPIN_DELAY_MS,

  /**
   * Set the broadcast function. Called by the WS layer on startup.
   * Signature: (broadcasterId, messageObj) => numberOfClientsReached
   */
  setBroadcaster(fn) {
    broadcastFn = fn;
  },

  /**
   * Get pending spin count for a streamer.
   */
  getPending(broadcasterId) {
    return getState(broadcasterId).pending_count;
  },

  /**
   * Get time (ms) until the next spin can be delivered.
   */
  getTimeUntilNextSpin(broadcasterId) {
    return getTimeUntilNextSpin(broadcasterId);
  },

  /** Deliver isolated preview spins without touching the production queue. */
  testSpin(broadcasterId, times = 1) {
    const safe = Math.max(1, Math.min(20, Math.round(Number(times) || 1)));
    let delivered = 0;
    for (let index = 0; index < safe; index++) {
      delivered = Math.max(delivered, broadcast(broadcasterId, buildSpinMessage(broadcasterId, null, { test: true })));
    }
    return delivered;
  },

  /**
   * Queue spins for a streamer and attempt to deliver one immediately.
   * @param {number} broadcasterId
   * @param {number} times  Number of spins to queue
   * @param {{ tier?: string }} [meta]  Optional metadata (tier name)
   * @returns {number} Number of clients that received a spin broadcast (0 if queued only)
   */
  deliverSpinOrQueue(broadcasterId, times, meta = {}) {
    const safe = Math.max(0, Number(times) || 0);
    if (!safe) return 0;

    // Queue tier info for each spin
    if (meta.tier) {
      const q = tierQueues.get(broadcasterId) || [];
      for (let i = 0; i < safe; i++) q.push(meta.tier);
      tierQueues.set(broadcasterId, q);
    }

    // Add to pending
    const state = getState(broadcasterId);
    const newPending = state.pending_count + safe;
    setState(broadcasterId, { pending_count: newPending });
    console.log(`[SPIN] bid=${broadcasterId} queued +${safe} (total pending=${newPending})${meta.tier ? ` tier="${meta.tier}"` : ""}`);

    // If a spin is in progress, just broadcast delay info
    if (isInProgress(broadcasterId)) {
      broadcast(broadcasterId, {
        type: "delay",
        timeUntilNext: Math.ceil(getTimeUntilNextSpin(broadcasterId) / 1000),
        pending: newPending,
      });
      return 0;
    }

    // Check delay
    const timeUntilNext = getTimeUntilNextSpin(broadcasterId);
    if (timeUntilNext > 0) {
      broadcast(broadcasterId, {
        type: "delay",
        timeUntilNext: Math.ceil(timeUntilNext / 1000),
        pending: newPending,
      });
      return 0;
    }

    // Deliver ONE spin (pop tier from queue)
    const tierName = (tierQueues.get(broadcasterId) || []).shift() || null;
    setState(broadcasterId, { pending_count: newPending - 1 });
    setInProgress(broadcasterId, true);
    const msg = buildSpinMessage(broadcasterId, tierName);
    const delivered = broadcast(broadcasterId, msg);
    if (delivered > 0) {
      console.log(`[SPIN] bid=${broadcasterId} delivered 1 spin (${newPending - 1} remaining)${tierName ? ` tier="${tierName}"` : ""}`);
    } else {
      // No clients connected — requeue (put tier back at front)
      setInProgress(broadcasterId, false);
      setState(broadcasterId, { pending_count: newPending });
      if (tierName) {
        const q = tierQueues.get(broadcasterId) || [];
        q.unshift(tierName);
        tierQueues.set(broadcasterId, q);
      }
      console.log(`[SPIN] bid=${broadcasterId} no clients, requeued (pending=${newPending})`);
    }
    return delivered;
  },

  /**
   * Reset the delay timer for a streamer so the next spin fires immediately.
   */
  resetDelay(broadcasterId) {
    setState(broadcasterId, { last_spin_time: 0 });
    setInProgress(broadcasterId, false);
    console.log(`[SPIN] bid=${broadcasterId} delay reset`);

    // If there are pending spins, try to deliver one right away
    const state = getState(broadcasterId);
    if (state.pending_count > 0) {
      const tierName = (tierQueues.get(broadcasterId) || []).shift() || null;
      setState(broadcasterId, { pending_count: state.pending_count - 1 });
      setInProgress(broadcasterId, true);
      const msg = buildSpinMessage(broadcasterId, tierName);
      const delivered = broadcast(broadcasterId, msg);
      if (delivered > 0) {
        console.log(`[SPIN] bid=${broadcasterId} delivered 1 after reset (${state.pending_count - 1} remaining)${tierName ? ` tier="${tierName}"` : ""}`);
      } else {
        setInProgress(broadcasterId, false);
        setState(broadcasterId, { pending_count: state.pending_count });
        if (tierName) {
          const q = tierQueues.get(broadcasterId) || [];
          q.unshift(tierName);
          tierQueues.set(broadcasterId, q);
        }
      }
    }
    // Notify delay overlay to clear
    broadcast(broadcasterId, { type: "delay", timeUntilNext: 0, pending: getState(broadcasterId).pending_count });
  },

  /**
   * Mark a spin as completed for a streamer. Starts the 5-minute delay.
   */
  markSpinComplete(broadcasterId) {
    setInProgress(broadcasterId, false);
    const now = Date.now();
    setState(broadcasterId, { last_spin_time: now, spin_in_progress: 0 });
    console.log(`[SPIN] bid=${broadcasterId} completed — delay timer started`);

    const state = getState(broadcasterId);
    if (state.pending_count > 0) {
      const timeUntilNext = getTimeUntilNextSpin(broadcasterId);
      broadcast(broadcasterId, {
        type: "delay",
        timeUntilNext: Math.ceil(timeUntilNext / 1000),
        pending: state.pending_count,
      });
      console.log(`[SPIN] bid=${broadcasterId} ${state.pending_count} pending, wait ${Math.ceil(timeUntilNext / 1000)}s`);
    }
  },
};

// ── Periodic checker ────────────────────────────────────────────────
// Iterates all streamers with pending spins and delivers when delay expires.

let _intervalId = null;

export function startSpinChecker() {
  if (_intervalId) return;
  _intervalId = setInterval(() => {
    let rows;
    try {
      rows = getDb().getStreamersWithPendingSpins();
    } catch {
      return; // DB not ready yet
    }
    for (const row of rows) {
      const bid = row.broadcaster_id;
      if (isInProgress(bid)) continue;
      if (getTimeUntilNextSpin(bid) > 0) {
        // Broadcast delay update
        broadcast(bid, {
          type: "delay",
          timeUntilNext: Math.ceil(getTimeUntilNextSpin(bid) / 1000),
          pending: row.pending_count,
        });
        continue;
      }
      // Deliver one spin (pop tier from queue)
      const state = getState(bid);
      if (state.pending_count <= 0) continue;
      const tierName = (tierQueues.get(bid) || []).shift() || null;
      setState(bid, { pending_count: state.pending_count - 1 });
      setInProgress(bid, true);
      const msg = buildSpinMessage(bid, tierName);
      const delivered = broadcast(bid, msg);
      if (delivered > 0) {
        console.log(`[SPIN][timer] bid=${bid} delivered 1 (${state.pending_count - 1} remaining)${tierName ? ` tier="${tierName}"` : ""}`);
      } else {
        setInProgress(bid, false);
        setState(bid, { pending_count: state.pending_count });
        if (tierName) {
          const q = tierQueues.get(bid) || [];
          q.unshift(tierName);
          tierQueues.set(bid, q);
        }
      }
    }
  }, 1000);
}

export function stopSpinChecker() {
  if (_intervalId) {
    clearInterval(_intervalId);
    _intervalId = null;
  }
}
