import { getDb } from "../db.js";

const SPIN_DELAY_MS = 5 * 60 * 1000; // 5 minutes

// Broadcast function set by the WebSocket layer: (broadcasterId, msg) => clientCount
let broadcastFn = null;

// In-memory spin-in-progress tracking per streamer (not persisted because
// a restart means no overlay is mid-spin anyway)
const inProgress = new Map();

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

  /**
   * Queue spins for a streamer and attempt to deliver one immediately.
   * @param {number} broadcasterId
   * @param {number} times  Number of spins to queue
   * @returns {number} Number of clients that received a spin broadcast (0 if queued only)
   */
  deliverSpinOrQueue(broadcasterId, times) {
    const safe = Math.max(0, Number(times) || 0);
    if (!safe) return 0;

    // Add to pending
    const state = getState(broadcasterId);
    const newPending = state.pending_count + safe;
    setState(broadcasterId, { pending_count: newPending });
    console.log(`[SPIN] bid=${broadcasterId} queued +${safe} (total pending=${newPending})`);

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

    // Deliver ONE spin
    setState(broadcasterId, { pending_count: newPending - 1 });
    setInProgress(broadcasterId, true);
    const delivered = broadcast(broadcasterId, { action: "spin", times: 1 });
    if (delivered > 0) {
      console.log(`[SPIN] bid=${broadcasterId} delivered 1 spin (${newPending - 1} remaining)`);
    } else {
      // No clients connected — requeue
      setInProgress(broadcasterId, false);
      setState(broadcasterId, { pending_count: newPending });
      console.log(`[SPIN] bid=${broadcasterId} no clients, requeued (pending=${newPending})`);
    }
    return delivered;
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
      // Deliver one spin
      const state = getState(bid);
      if (state.pending_count <= 0) continue;
      setState(bid, { pending_count: state.pending_count - 1 });
      setInProgress(bid, true);
      const delivered = broadcast(bid, { action: "spin", times: 1 });
      if (delivered > 0) {
        console.log(`[SPIN][timer] bid=${bid} delivered 1 (${state.pending_count - 1} remaining)`);
      } else {
        setInProgress(bid, false);
        setState(bid, { pending_count: state.pending_count });
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
