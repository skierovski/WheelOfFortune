import { getDb } from "../db.js";
import { issueOverlayTicket } from "./overlayTickets.js";

export const SLOTS_DELAY_MS = 30 * 1000; // 30s between slot spins
export const BET = 0.2;
export const REELS = 5;
export const ROWS = 3;
export const PAY_ROW = 1; // middle row

export const SYMBOLS = ["cherry", "lemon", "orange", "plum", "melon", "grapes", "dollar"];

/** Relative weights for RNG (common fruits more often). */
const WEIGHTS = {
  cherry: 28,
  lemon: 24,
  orange: 18,
  plum: 14,
  melon: 8,
  grapes: 6,
  dollar: 2,
};

/** Multipliers × BET for consecutive L→R matches on middle payline. */
export const PAYTABLE = {
  cherry: { 3: 2, 4: 5, 5: 20 },
  lemon: { 3: 2, 4: 5, 5: 20 },
  orange: { 3: 3, 4: 8, 5: 25 },
  plum: { 3: 3, 4: 8, 5: 25 },
  melon: { 3: 5, 4: 15, 5: 40 },
  grapes: { 3: 5, 4: 15, 5: 40 },
  dollar: { 3: 20, 4: 50, 5: 100 },
};

let broadcastFn = null;
const inProgress = new Map();
const inProgressAt = new Map();
const SPIN_STALE_MS = 25 * 1000;

function markInProgress(broadcasterId, value) {
  inProgress.set(broadcasterId, value);
  if (value) inProgressAt.set(broadcasterId, Date.now());
  else inProgressAt.delete(broadcasterId);
}

function recoverIfStaleInProgress(broadcasterId) {
  if (!inProgress.get(broadcasterId)) return false;
  const startedAt = inProgressAt.get(broadcasterId) || 0;
  const age = Date.now() - startedAt;
  if (age < SPIN_STALE_MS) return false;
  console.warn(`[SLOTS] bid=${broadcasterId} stale in_progress (${age}ms) -> recovering`);
  markInProgress(broadcasterId, false);
  const state = getDb().getSlotsState(broadcasterId);
  getDb().saveSlotsState(broadcasterId, { ...state, spin_in_progress: 0 });
  return true;
}

function broadcast(broadcasterId, msg) {
  if (!broadcastFn) return 0;
  return broadcastFn(broadcasterId, msg) || 0;
}

function pickSymbol() {
  let total = 0;
  for (const s of SYMBOLS) total += WEIGHTS[s];
  let r = Math.random() * total;
  for (const s of SYMBOLS) {
    r -= WEIGHTS[s];
    if (r <= 0) return s;
  }
  return SYMBOLS[0];
}

/**
 * Build 5×3 grid (columns of rows). grid[reel][row]
 */
export function rollGrid() {
  const grid = [];
  for (let c = 0; c < REELS; c++) {
    const col = [];
    for (let r = 0; r < ROWS; r++) col.push(pickSymbol());
    grid.push(col);
  }
  return grid;
}

/**
 * Evaluate one horizontal row: any consecutive streak of 3+ matching symbols
 * (not only left-to-right from reel 0 — e.g. X L L L L still pays).
 */
function evaluateRow(grid, row) {
  const line = grid.map((col) => col[row]);
  let best = { win: 0, matchCount: 0, symbol: null, line, row, start: 0 };

  let i = 0;
  while (i < line.length) {
    const symbol = line[i];
    let matchCount = 1;
    while (i + matchCount < line.length && line[i + matchCount] === symbol) {
      matchCount++;
    }
    if (matchCount >= 3) {
      const keyed = Math.min(matchCount, 5);
      const mult = PAYTABLE[symbol]?.[keyed] || 0;
      const win = Math.round(BET * mult * 100) / 100;
      if (win > best.win || (win === best.win && matchCount > best.matchCount)) {
        best = { win, matchCount, symbol, line, row, start: i };
      }
    }
    i += matchCount;
  }

  if (best.matchCount < 3) {
    return { win: 0, matchCount: 0, symbol: null, line, row, start: 0 };
  }
  return best;
}

/**
 * Evaluate all 3 rows (paylines). Any 3+ in a row pays and grants a bonus spin.
 * @returns {{ win: number, matchCount: number, symbol: string|null, line: string[], rows: number[], bonus: boolean, hits: Array }}
 */
export function evaluatePayline(grid) {
  const hits = [];
  let totalWin = 0;
  let best = null;
  for (let row = 0; row < ROWS; row++) {
    const r = evaluateRow(grid, row);
    if (r.win > 0) {
      hits.push(r);
      totalWin = roundMoney(totalWin + r.win);
      if (!best || r.matchCount > best.matchCount || (r.matchCount === best.matchCount && r.win > best.win)) {
        best = r;
      }
    }
  }
  if (!hits.length) {
    return { win: 0, matchCount: 0, symbol: null, line: grid.map((c) => c[PAY_ROW]), rows: [], bonus: false, hits: [] };
  }
  return {
    win: totalWin,
    matchCount: best.matchCount,
    symbol: best.symbol,
    line: best.line,
    rows: hits.map((h) => h.row),
    bonus: true, // 3+ fruits in a row → free bonus spin
    hits,
  };
}

function getTimeUntilNext(broadcasterId) {
  const state = getDb().getSlotsState(broadcasterId);
  const elapsed = Date.now() - (state.last_spin_time || 0);
  if (elapsed >= SLOTS_DELAY_MS) return 0;
  return SLOTS_DELAY_MS - elapsed;
}

function roundMoney(n) {
  return Math.round(Number(n) * 100) / 100;
}

/**
 * Apply win to bank and return newly unlocked prizes.
 */
function applyWinAndPrizes(broadcasterId, win) {
  const db = getDb();
  const state = db.getSlotsState(broadcasterId);
  const config = db.getConfig(broadcasterId);
  const prizes = Array.isArray(config?.slots_prizes) ? config.slots_prizes : [];
  const claimed = new Set((state.claimed || []).map(Number));

  const bank = roundMoney((state.bank || 0) + (win || 0));
  const hit = [];
  for (const p of prizes) {
    const min = Number(p.min_bank);
    if (!Number.isFinite(min) || min <= 0) continue;
    if (bank >= min && !claimed.has(min)) {
      hit.push({ min_bank: min, label: String(p.label || "") });
      claimed.add(min);
    }
  }
  hit.sort((a, b) => a.min_bank - b.min_bank);

  db.saveSlotsState(broadcasterId, {
    bank,
    claimed: [...claimed].sort((a, b) => a - b),
    pending_count: state.pending_count,
    last_spin_time: state.last_spin_time,
    spin_in_progress: state.spin_in_progress,
  });

  return { bank, prizes_hit: hit };
}

function deliverOne(broadcasterId, { skipDelay = false } = {}) {
  const db = getDb();
  recoverIfStaleInProgress(broadcasterId);
  const state = db.getSlotsState(broadcasterId);
  if (state.pending_count <= 0) return 0;
  if (inProgress.get(broadcasterId)) return 0;

  if (!skipDelay) {
    const wait = getTimeUntilNext(broadcasterId);
    if (wait > 0) {
      broadcast(broadcasterId, {
        type: "slots_delay",
        timeUntilNext: Math.ceil(wait / 1000),
        pending: state.pending_count,
        bank: state.bank,
      });
      return 0;
    }
  }

  const grid = rollGrid();
  const evalResult = evaluatePayline(grid);
  const { bank, prizes_hit } = applyWinAndPrizes(broadcasterId, evalResult.win);
  const cfg = db.getConfig(broadcasterId);

  const newPending = state.pending_count - 1;
  markInProgress(broadcasterId, true);
  db.saveSlotsState(broadcasterId, {
    bank,
    claimed: db.getSlotsState(broadcasterId).claimed,
    pending_count: newPending,
    last_spin_time: state.last_spin_time,
    spin_in_progress: 1,
  });

  const token = cfg?.slots_token || "🪙";
  const prizeLabels = prizes_hit.map((prize) => prize.label).filter(Boolean);
  const announceLabel = prizeLabels.length
    ? `Slots prize: ${prizeLabels.join(" · ")} (bank ${token}${bank})`
    : evalResult.win > 0
      ? `Slots win ${token}${evalResult.win}${evalResult.bonus ? " (+bonus)" : ""} (bank ${token}${bank})`
      : "";
  const msg = {
    action: "slots",
    times: 1,
    ticket: issueOverlayTicket({
      broadcasterId,
      kind: "slots",
      announceLabel,
      metadata: { bonus: !!evalResult.bonus },
    }),
    result: {
      grid,
      win: evalResult.win,
      matchCount: evalResult.matchCount,
      symbol: evalResult.symbol,
      line: evalResult.line,
      rows: evalResult.rows || [],
      hits: evalResult.hits || [],
      bonus: !!evalResult.bonus,
      bank,
      prizes_hit,
      bet: BET,
      slots_token: token,
    },
  };

  const delivered = broadcast(broadcasterId, msg);
  if (delivered > 0) {
    console.log(
      `[SLOTS] bid=${broadcasterId} delivered win=${token}${evalResult.win} bank=${token}${bank} pending=${newPending}` +
        (prizes_hit.length ? ` prizes=[${prizes_hit.map((p) => p.label).join(",")}]` : "")
    );
  } else {
    // No overlay connected — requeue and roll back bank/claimed from this attempt
    markInProgress(broadcasterId, false);
    // Simpler: keep bank update (money already "won") but requeue pending
    // Actually if no client, we should undo the bank change for fairness on retry.
    // Re-roll on next deliver is fine; undo bank:
    const claimedNow = db.getSlotsState(broadcasterId).claimed || [];
    const undoneBank = roundMoney(bank - evalResult.win);
    const undoneClaimed = claimedNow.filter(
      (m) => !prizes_hit.some((p) => p.min_bank === m)
    );
    db.saveSlotsState(broadcasterId, {
      bank: undoneBank,
      claimed: undoneClaimed,
      pending_count: state.pending_count,
      last_spin_time: state.last_spin_time,
      spin_in_progress: 0,
    });
    console.log(`[SLOTS] bid=${broadcasterId} no clients, requeued (pending=${state.pending_count})`);
  }
  return delivered;
}

export const slots = {
  SLOTS_DELAY_MS,
  BET,
  SYMBOLS,
  PAYTABLE,

  setBroadcaster(fn) {
    broadcastFn = fn;
  },

  getPending(broadcasterId) {
    return getDb().getSlotsState(broadcasterId).pending_count;
  },

  getBank(broadcasterId) {
    return getDb().getSlotsState(broadcasterId).bank;
  },

  getState(broadcasterId) {
    const s = getDb().getSlotsState(broadcasterId);
    const cfg = getDb().getConfig(broadcasterId);
    return {
      bank: s.bank,
      claimed: s.claimed,
      pending_count: s.pending_count,
      timeUntilNext: Math.ceil(getTimeUntilNext(broadcasterId) / 1000),
      prizes: cfg?.slots_prizes || [],
      slots_token: cfg?.slots_token || "🪙",
    };
  },

  getTimeUntilNext(broadcasterId) {
    return getTimeUntilNext(broadcasterId);
  },

  /**
   * Queue slot spins and try to deliver one.
   * @param {number} broadcasterId
   * @param {number} times
   * @param {{ skipDelay?: boolean }} [opts]
   */
  deliverOrQueue(broadcasterId, times, opts = {}) {
    const safe = Math.max(0, Math.min(100, Number(times) || 0));
    if (!safe) return 0;

    const db = getDb();
    recoverIfStaleInProgress(broadcasterId);
    const state = db.getSlotsState(broadcasterId);
    const newPending = state.pending_count + safe;
    db.saveSlotsState(broadcasterId, {
      ...state,
      pending_count: newPending,
    });
    console.log(`[SLOTS] bid=${broadcasterId} queued +${safe} (total pending=${newPending})`);

    if (inProgress.get(broadcasterId)) {
      broadcast(broadcasterId, {
        type: "slots_delay",
        timeUntilNext: Math.ceil(getTimeUntilNext(broadcasterId) / 1000),
        pending: newPending,
        bank: state.bank,
      });
      return 0;
    }

    return deliverOne(broadcasterId, { skipDelay: !!opts.skipDelay });
  },

  /**
   * Test spin: queue + deliver immediately (skip delay).
   */
  testSpin(broadcasterId, n = 1) {
    return this.deliverOrQueue(broadcasterId, n, { skipDelay: true });
  },

  /**
   * Mark spin complete. If bonus (3+ in a row), queue an immediate free spin (no delay).
   * @param {number} broadcasterId
   * @param {{ bonus?: boolean }} [opts]
   */
  markComplete(broadcasterId, opts = {}) {
    markInProgress(broadcasterId, false);
    const db = getDb();
    const state = db.getSlotsState(broadcasterId);
    const bonus = !!opts.bonus;

    if (bonus) {
      // Free re-spin: do not start the cooldown; queue + deliver now
      db.saveSlotsState(broadcasterId, {
        ...state,
        last_spin_time: 0,
        spin_in_progress: 0,
        pending_count: state.pending_count + 1,
      });
      console.log(`[SLOTS] bid=${broadcasterId} WIN bonus → free spin queued`);
      deliverOne(broadcasterId, { skipDelay: true });
      return;
    }

    const now = Date.now();
    db.saveSlotsState(broadcasterId, {
      ...state,
      last_spin_time: now,
      spin_in_progress: 0,
    });
    console.log(`[SLOTS] bid=${broadcasterId} completed — delay timer started`);

    if (state.pending_count > 0) {
      broadcast(broadcasterId, {
        type: "slots_delay",
        timeUntilNext: Math.ceil(SLOTS_DELAY_MS / 1000),
        pending: state.pending_count,
        bank: state.bank,
      });
    }
  },

  resetBank(broadcasterId) {
    const db = getDb();
    const state = db.getSlotsState(broadcasterId);
    db.saveSlotsState(broadcasterId, {
      ...state,
      bank: 0,
      claimed: [],
    });
    broadcast(broadcasterId, {
      type: "slots_bank",
      bank: 0,
      claimed: [],
      prizes_hit: [],
    });
    console.log(`[SLOTS] bid=${broadcasterId} bank reset`);
    return { bank: 0, claimed: [] };
  },

  resetDelay(broadcasterId) {
    const db = getDb();
    const state = db.getSlotsState(broadcasterId);
    markInProgress(broadcasterId, false);
    db.saveSlotsState(broadcasterId, {
      ...state,
      last_spin_time: 0,
      spin_in_progress: 0,
    });
    if (state.pending_count > 0) {
      deliverOne(broadcasterId, { skipDelay: true });
    }
    broadcast(broadcasterId, {
      type: "slots_delay",
      timeUntilNext: 0,
      pending: db.getSlotsState(broadcasterId).pending_count,
      bank: db.getSlotsState(broadcasterId).bank,
    });
  },
};

let _intervalId = null;

export function startSlotsChecker() {
  if (_intervalId) return;
  _intervalId = setInterval(() => {
    let rows;
    try {
      rows = getDb().getStreamersWithPendingSlots();
    } catch {
      return;
    }
    for (const row of rows) {
      const bid = row.broadcaster_id;
      recoverIfStaleInProgress(bid);
      if (inProgress.get(bid)) continue;
      deliverOne(bid);
    }
  }, 1000);
}

export function stopSlotsChecker() {
  if (_intervalId) {
    clearInterval(_intervalId);
    _intervalId = null;
  }
}
